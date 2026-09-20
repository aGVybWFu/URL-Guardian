"""URLBERT encoder wrapper with a task-specific three-class head.

The upstream repository ships several pretrained heads trained on other
datasets (two-class, four-class, 17-class, ...). This project deliberately does
not reuse them: it builds a new three-class head (`BENIGN`, `PHISHING`,
`MALWARE`) and fine-tunes it on the frozen URL Guardian Train Set only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch
from torch import nn

NUM_CLASSES = 3
DEFAULT_POOLING = "cls_mean"


@dataclass(frozen=True)
class EncoderSpec:
    """Description of the pretrained encoder actually loaded."""

    name: str
    revision: str
    hidden_size: int
    num_hidden_layers: int
    num_attention_heads: int
    vocab_size: int
    architecture: str
    params: int


def load_encoder(name: str, revision: str) -> tuple[nn.Module, EncoderSpec]:
    """Load the frozen pretrained encoder at a pinned revision."""

    from transformers import AutoModel

    encoder = AutoModel.from_pretrained(name, revision=revision)
    config = encoder.config
    spec = EncoderSpec(
        name=name,
        revision=revision,
        hidden_size=int(config.hidden_size),
        num_hidden_layers=int(config.num_hidden_layers),
        num_attention_heads=int(config.num_attention_heads),
        vocab_size=int(config.vocab_size),
        architecture=type(encoder).__name__,
        params=int(sum(parameter.numel() for parameter in encoder.parameters())),
    )
    return encoder, spec


class URLBertClassifier(nn.Module):
    """Pretrained encoder plus a newly initialized three-class classification head."""

    def __init__(
        self,
        encoder: nn.Module,
        *,
        num_classes: int = NUM_CLASSES,
        hidden_size: int = 256,
        dropout: float = 0.1,
        pooling: str = DEFAULT_POOLING,
    ) -> None:
        super().__init__()
        if pooling != DEFAULT_POOLING:
            raise ValueError(f"Unsupported pooling strategy: {pooling}")
        self.encoder = encoder
        self.pooling = pooling
        self.num_classes = num_classes
        encoder_dim = int(encoder.config.hidden_size)
        # CLS + MEAN pooling concatenates the [CLS] representation with the
        # masked mean of all token representations (the upstream model card
        # recommends this combination for downstream tasks).
        self.pooled_dim = encoder_dim * 2
        self.classifier = nn.Sequential(
            nn.Linear(self.pooled_dim, hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes),
        )

    def pool(self, last_hidden_state: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        mask = attention_mask.unsqueeze(-1).to(last_hidden_state.dtype)
        cls = last_hidden_state[:, 0, :]
        summed = (last_hidden_state * mask).sum(dim=1)
        counts = mask.sum(dim=1).clamp(min=1e-6)
        mean = summed / counts
        return torch.cat([cls, mean], dim=-1)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = self.pool(outputs.last_hidden_state, attention_mask)
        return self.classifier(pooled)

    def probabilities(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Softmax probabilities (not logits)."""

        return torch.softmax(self.forward(input_ids, attention_mask), dim=-1)

    def trainable_parameters(self) -> int:
        return int(sum(parameter.numel() for parameter in self.parameters() if parameter.requires_grad))

    def total_parameters(self) -> int:
        return int(sum(parameter.numel() for parameter in self.parameters()))


@dataclass
class CheckpointInfo:
    """Metadata recorded alongside a saved checkpoint."""

    experiment_id: str
    epoch: int
    validation_macro_f1: float
    extra: dict[str, Any] = field(default_factory=dict)


def save_checkpoint(
    directory: str | Path,
    name: str,
    model: URLBertClassifier,
    tokenizer: object,
    info: CheckpointInfo,
) -> Path:
    """Persist one checkpoint (weights + tokenizer + config + metadata)."""

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    weights_path = target / f"{name}.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "pooling": model.pooling,
            "num_classes": model.num_classes,
            "epoch": info.epoch,
            "validation_macro_f1": info.validation_macro_f1,
            "experiment_id": info.experiment_id,
        },
        weights_path,
    )
    tokenizer.save_pretrained(target / f"{name}_tokenizer")
    return weights_path


def load_checkpoint(path: str | Path, encoder_name: str, encoder_revision: str) -> tuple[URLBertClassifier, dict[str, Any]]:
    """Rebuild the classifier from a checkpoint produced by `save_checkpoint`."""

    payload = torch.load(Path(path), map_location="cpu", weights_only=True)
    encoder, _ = load_encoder(encoder_name, encoder_revision)
    model = URLBertClassifier(
        encoder,
        num_classes=int(payload.get("num_classes", NUM_CLASSES)),
        pooling=str(payload.get("pooling", DEFAULT_POOLING)),
        hidden_size=int(payload["state_dict"]["classifier.0.weight"].shape[0]),
        dropout=0.0,
    )
    model.load_state_dict(payload["state_dict"])
    return model, payload
