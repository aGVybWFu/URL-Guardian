"""Out-of-fold URLBERT probabilities for UGDM.

UGDM consumes a URLBERT probability as a feature. Using the official URLBERT's
prediction on rows it was trained on would leak the label into the feature
(stacking leakage). Every UGDM Train row therefore receives a probability from a
model that never saw that row or its registrable domain.

Fold protocol:

* 5-fold group split on `registrable_domain` inside the frozen Train partition.
* Each fold model trains on the other folds only, with a fixed epoch budget.
* The held-out fold is predicted by that fold model.
* Validation features come from a model trained on the full Train split with the
  same fixed epoch budget, so Validation never influences base-model fitting.
* Test features come from the already-frozen official binary checkpoint, which
  never saw Test during training or selection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from src.data.snapshot import sha256_file
from src.models.urlbert.config import URLBERTConfig, load_urlbert_config
from src.models.urlbert.dataset import tokenize_frame
from src.models.urlbert.model import URLBertClassifier, load_encoder
from src.models.urlbert.train import (
    evaluate_split,
    resolve_amp_dtype,
    set_deterministic_seed,
)
from src.utils.logging import configure_logging, get_logger

LOGGER = get_logger(__name__)
OOF_STRATEGY = "5-fold_group_kfold_on_registrable_domain_within_frozen_train"
OOF_EPOCHS = 4


@dataclass(frozen=True)
class FoldAssignment:
    """Deterministic fold membership for the frozen Train partition."""

    fold: int
    train_index: list[int]
    holdout_index: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fold": self.fold,
            "trainCount": len(self.train_index),
            "holdoutCount": len(self.holdout_index),
        }


def group_kfold_assignments(
    frame: pd.DataFrame,
    n_splits: int = 5,
    seed: int = 42,
    group_column: str = "registrable_domain",
) -> list[FoldAssignment]:
    """Assign every Train row to exactly one held-out fold.

    Groups are ordered deterministically and dealt round-robin so the result does
    not depend on pandas or sklearn version details.
    """

    if n_splits < 2:
        raise ValueError("n_splits must be at least 2")
    groups = sorted(frame[group_column].astype(str).unique())
    if len(groups) < n_splits:
        raise ValueError("Not enough registrable domains for the requested fold count")
    rng = np.random.default_rng(seed)
    shuffled = list(groups)
    rng.shuffle(shuffled)
    fold_of_group = {group: index % n_splits for index, group in enumerate(shuffled)}

    domain_values = frame[group_column].astype(str)
    fold_values = domain_values.map(fold_of_group)
    assignments: list[FoldAssignment] = []
    for fold in range(n_splits):
        holdout_index = [int(value) for value in frame.index[fold_values == fold]]
        train_index = [int(value) for value in frame.index[fold_values != fold]]
        assignments.append(FoldAssignment(fold=fold, train_index=train_index, holdout_index=holdout_index))
    return assignments


def assert_fold_integrity(
    frame: pd.DataFrame,
    assignments: list[FoldAssignment],
    group_column: str = "registrable_domain",
) -> dict[str, Any]:
    """Verify every row is covered once and no domain crosses the fold boundary."""

    covered: list[int] = []
    domain_overlap_total = 0
    for assignment in assignments:
        covered.extend(assignment.holdout_index)
        train_domains = set(frame.loc[assignment.train_index, group_column].astype(str))
        holdout_domains = set(frame.loc[assignment.holdout_index, group_column].astype(str))
        overlap = train_domains & holdout_domains
        if overlap:
            raise RuntimeError(
                f"Fold {assignment.fold} has registrable-domain leakage: {len(overlap)} domains"
            )
        domain_overlap_total += len(overlap)
    if sorted(covered) != sorted(int(value) for value in frame.index):
        raise RuntimeError("Out-of-fold coverage is incomplete: every Train row must be held out exactly once")
    if len(covered) != len(set(covered)):
        raise RuntimeError("A Train row was assigned to more than one held-out fold")
    return {
        "rowsCovered": len(covered),
        "uniqueRowsCovered": len(set(covered)),
        "domainOverlap": domain_overlap_total,
        "rowLeakage": 0,
    }


def _train_fold_model(
    config: URLBERTConfig,
    train_frame: pd.DataFrame,
    epochs: int,
    seed: int,
    tokenizer: object,
    device: torch.device,
) -> URLBertClassifier:
    """Train one fold model with a fixed recipe and a fixed epoch budget."""

    set_deterministic_seed(seed)
    amp_dtype = resolve_amp_dtype(str(config.training.get("mixed_precision", "auto")))
    tokenized = tokenize_frame(train_frame, "fold_train", config, tokenizer)
    encoder, _ = load_encoder(config.base_model, config.base_model_revision)
    model = URLBertClassifier(
        encoder,
        num_classes=config.num_classes,
        hidden_size=config.head_hidden_size,
        dropout=config.head_dropout,
        pooling=config.pooling,
    ).to(device)

    batch_size = 512
    learning_rate = float(config.training["learning_rate"])
    weight_decay = float(config.training["weight_decay"])
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    steps_per_epoch = max(1, int(np.ceil(len(tokenized) / batch_size)))
    total_steps = steps_per_epoch * epochs
    warmup_steps = max(1, int(total_steps * float(config.training.get("warmup_ratio", 0.1))))

    def schedule(step: int) -> float:
        if step < warmup_steps:
            return float(step) / float(warmup_steps)
        return max(0.0, float(total_steps - step) / float(max(1, total_steps - warmup_steps)))

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, schedule)
    criterion = nn.CrossEntropyLoss()
    use_scaler = amp_dtype == torch.float16
    scaler = torch.amp.GradScaler("cuda", enabled=use_scaler)

    dataset = TensorDataset(tokenized.input_ids, tokenized.attention_mask, tokenized.labels)
    generator = torch.Generator()
    generator.manual_seed(seed)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, generator=generator)

    model.train()
    for _ in range(epochs):
        for batch_ids, batch_mask, batch_labels in loader:
            batch_ids = batch_ids.to(device)
            batch_mask = batch_mask.to(device)
            batch_labels = batch_labels.to(device)
            with torch.autocast(device_type="cuda", dtype=amp_dtype, enabled=amp_dtype is not None):
                logits = model(batch_ids, batch_mask)
                loss = criterion(logits, batch_labels)
            if use_scaler:
                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
            else:
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
            optimizer.zero_grad(set_to_none=True)
            scheduler.step()
    return model


@torch.no_grad()
def _predict_probabilities(
    model: URLBertClassifier,
    config: URLBERTConfig,
    frame: pd.DataFrame,
    tokenizer: object,
    device: torch.device,
    batch_size: int = 512,
) -> np.ndarray:
    model.eval()
    tokenized = tokenize_frame(frame, "predict", config, tokenizer)
    outputs: list[np.ndarray] = []
    for start in range(0, len(tokenized), batch_size):
        stop = start + batch_size
        logits = model(
            tokenized.input_ids[start:stop].to(device),
            tokenized.attention_mask[start:stop].to(device),
        )
        outputs.append(torch.softmax(logits.float(), dim=-1).cpu().numpy())
    return np.concatenate(outputs, axis=0)


def build_oof_features(
    config_path: str | Path,
    output_dir: str | Path,
    n_splits: int = 5,
    epochs: int = OOF_EPOCHS,
) -> dict[str, Any]:
    """Generate out-of-fold Train probabilities plus Validation and Test features."""

    configure_logging()
    config = load_urlbert_config(config_path)
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for the URLBERT out-of-fold pipeline")
    device = torch.device("cuda")
    seed = config.seed

    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(config.base_model, revision=config.base_model_revision)
    train_frame = pd.read_csv(config.splits_dir / "train.csv", dtype=str, low_memory=False)
    validation_frame = pd.read_csv(config.splits_dir / "validation.csv", dtype=str, low_memory=False)
    test_frame = pd.read_csv(config.splits_dir / "test.csv", dtype=str, low_memory=False)

    assignments = group_kfold_assignments(train_frame, n_splits=n_splits, seed=seed)
    integrity = assert_fold_integrity(train_frame, assignments)

    oof_probabilities = np.zeros((len(train_frame), config.num_classes), dtype=float)
    fold_metadata: list[dict[str, Any]] = []
    for assignment in assignments:
        fold_train = train_frame.iloc[assignment.train_index].reset_index(drop=True)
        fold_holdout = train_frame.iloc[assignment.holdout_index].reset_index(drop=True)
        model = _train_fold_model(config, fold_train, epochs, seed + assignment.fold, tokenizer, device)
        probabilities = _predict_probabilities(model, config, fold_holdout, tokenizer, device)
        for position, row_index in enumerate(assignment.holdout_index):
            oof_probabilities[row_index] = probabilities[position]
        holdout_labels = fold_holdout["label"].map(config.label_mapping).to_numpy(dtype=int)
        fold_metrics = evaluate_split(
            model,
            tokenize_frame(fold_holdout, "fold_holdout", config, tokenizer).input_ids,
            tokenize_frame(fold_holdout, "fold_holdout", config, tokenizer).attention_mask,
            torch.tensor(holdout_labels),
            512,
            device,
            resolve_amp_dtype(str(config.training.get("mixed_precision", "auto"))),
            config.num_classes,
        )
        fold_metadata.append(
            {
                **assignment.to_dict(),
                "holdoutAccuracy": fold_metrics["accuracy"],
                "holdoutF1": fold_metrics["f1"],
                "holdoutAuprc": fold_metrics.get("auprc"),
                "trainDomains": int(fold_train["registrable_domain"].nunique()),
                "holdoutDomains": int(fold_holdout["registrable_domain"].nunique()),
                "domainOverlap": 0,
            }
        )
        LOGGER.info(
            "fold %d/%d holdout F1 %.6f",
            assignment.fold + 1,
            n_splits,
            fold_metrics["f1"],
        )

    validation_model = _train_fold_model(config, train_frame, epochs, seed, tokenizer, device)
    validation_probabilities = _predict_probabilities(
        model=validation_model, config=config, frame=validation_frame, tokenizer=tokenizer, device=device
    )

    official_checkpoint = config.path("checkpoint_dir") / "best.pt"
    if not official_checkpoint.exists():
        raise FileNotFoundError("The official binary URLBERT checkpoint is required for Test features")
    from src.models.urlbert.model import load_checkpoint

    official_model, _ = load_checkpoint(official_checkpoint, config.base_model, config.base_model_revision)
    official_model.to(device)
    test_probabilities = _predict_probabilities(
        model=official_model, config=config, frame=test_frame, tokenizer=tokenizer, device=device
    )

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    oof_frame = pd.DataFrame(
        {
            "rowId": [f"train:{index}" for index in range(len(train_frame))],
            "registrable_domain": train_frame["registrable_domain"].astype(str),
            "label": train_frame["label"].astype(str),
            "source": train_frame["source"].astype(str),
            "fold": [assignments[0].fold] * len(train_frame),
            "phishing_probability": oof_probabilities[:, 1],
            "benign_probability": oof_probabilities[:, 0],
        }
    )
    fold_lookup = {
        row_index: assignment.fold
        for assignment in assignments
        for row_index in assignment.holdout_index
    }
    oof_frame["fold"] = [fold_lookup[index] for index in range(len(train_frame))]
    oof_frame.to_csv(directory / "oof_train_probabilities.csv", index=False)
    pd.DataFrame(
        {
            "rowId": [f"validation:{index}" for index in range(len(validation_frame))],
            "registrable_domain": validation_frame["registrable_domain"].astype(str),
            "label": validation_frame["label"].astype(str),
            "phishing_probability": validation_probabilities[:, 1],
            "benign_probability": validation_probabilities[:, 0],
        }
    ).to_csv(directory / "validation_probabilities.csv", index=False)
    pd.DataFrame(
        {
            "rowId": [f"test:{index}" for index in range(len(test_frame))],
            "registrable_domain": test_frame["registrable_domain"].astype(str),
            "label": test_frame["label"].astype(str),
            "phishing_probability": test_probabilities[:, 1],
            "benign_probability": test_probabilities[:, 0],
        }
    ).to_csv(directory / "test_probabilities.csv", index=False)

    payload = {
        "oofStrategy": OOF_STRATEGY,
        "foldCount": n_splits,
        "seed": seed,
        "epochsPerFold": epochs,
        "foldIntegrity": integrity,
        "folds": fold_metadata,
        "trainRowCount": int(len(train_frame)),
        "validationRowCount": int(len(validation_frame)),
        "testRowCount": int(len(test_frame)),
        "testFeatureSource": "official binary checkpoint trained on the full frozen Train split",
        "validationFeatureSource": "fold-style model trained on the full frozen Train split, fixed epochs, no early stopping",
        "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "datasetVersion": config.dataset_version,
        "testManifestSHA256": sha256_file(config.raw_path("test_manifest")),
        "baseModel": config.base_model,
        "baseModelRevision": config.base_model_revision,
        "note": (
            "Every Train row receives a probability from a model that never saw that row or its "
            "registrable domain. Validation and Test rows never influenced base-model fitting."
        ),
    }
    (directory / "oof_metadata.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return payload
