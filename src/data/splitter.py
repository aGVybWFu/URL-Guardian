from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


def assert_no_domain_leakage(train: pd.DataFrame, validation: pd.DataFrame, test: pd.DataFrame) -> None:
    domains = [set(part["registrable_domain"].dropna()) for part in (train, validation, test)]
    overlaps = {
        "train_validation": domains[0].intersection(domains[1]),
        "train_test": domains[0].intersection(domains[2]),
        "validation_test": domains[1].intersection(domains[2]),
    }
    leaking = {name: values for name, values in overlaps.items() if values}
    if leaking:
        counts = ", ".join(f"{name}={len(values)}" for name, values in leaking.items())
        raise RuntimeError(f"Registrable-domain leakage detected: {counts}")


def _score(parts: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame], ratios: tuple[float, float, float]) -> float:
    total = sum(len(part) for part in parts)
    labels = sorted(set().union(*(set(part["label"]) for part in parts)))
    score = sum(abs(len(part) / total - ratio) for part, ratio in zip(parts, ratios))
    overall = pd.concat(parts)["label"].value_counts(normalize=True)
    for part in parts:
        distribution = part["label"].value_counts(normalize=True)
        score += sum(abs(float(distribution.get(label, 0)) - float(overall.get(label, 0))) for label in labels)
        score += 5.0 * sum(label not in set(part["label"]) for label in labels)
    return score


def domain_aware_split(
    frame: pd.DataFrame,
    train_ratio: float = 0.70,
    validation_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    if abs(train_ratio + validation_ratio + test_ratio - 1.0) > 1e-9:
        raise ValueError("Split ratios must sum to 1")
    if frame["registrable_domain"].nunique() < 4:
        raise ValueError("At least four unique registrable domains are required")
    holdout_ratio = validation_ratio + test_ratio
    outer = GroupShuffleSplit(n_splits=64, test_size=holdout_ratio, random_state=seed)
    best: tuple[float, tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]] | None = None
    groups = frame["registrable_domain"]
    for attempt, (train_idx, holdout_idx) in enumerate(outer.split(frame, frame["label"], groups)):
        train = frame.iloc[train_idx]
        holdout = frame.iloc[holdout_idx]
        relative_test = test_ratio / holdout_ratio
        inner = GroupShuffleSplit(n_splits=1, test_size=relative_test, random_state=seed + attempt)
        val_idx, test_idx = next(inner.split(holdout, holdout["label"], holdout["registrable_domain"]))
        validation = holdout.iloc[val_idx]
        test = holdout.iloc[test_idx]
        parts = (train, validation, test)
        candidate = _score(parts, (train_ratio, validation_ratio, test_ratio))
        if best is None or candidate < best[0]:
            best = (candidate, parts)
    if best is None:
        raise RuntimeError("Unable to create a registrable-domain-aware split")
    train, validation, test = (part.sample(frac=1, random_state=seed).reset_index(drop=True) for part in best[1])
    assert_no_domain_leakage(train, validation, test)
    return train, validation, test


def save_splits(parts: tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame], output_dir: str | Path) -> None:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for name, frame in zip(("train", "validation", "test"), parts):
        frame.to_csv(directory / f"{name}.csv", index=False, lineterminator="\n")
