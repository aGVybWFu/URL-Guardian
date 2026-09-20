from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_confusion_matrix(matrix: list[list[int]], class_names: list[str], output: str | Path) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    values = np.asarray(matrix)
    figure, axis = plt.subplots(figsize=(7, 6))
    image = axis.imshow(values, interpolation="nearest", cmap="Blues")
    figure.colorbar(image, ax=axis)
    axis.set(title="URL Guardian Confusion Matrix", xlabel="Predicted class", ylabel="True class")
    axis.set_xticks(range(len(class_names)), class_names, rotation=25, ha="right")
    axis.set_yticks(range(len(class_names)), class_names)
    threshold = values.max() / 2 if values.size else 0
    for row in range(values.shape[0]):
        for column in range(values.shape[1]):
            axis.text(column, row, str(values[row, column]), ha="center", va="center",
                      color="white" if values[row, column] > threshold else "black")
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


def plot_feature_importance(frame: pd.DataFrame, output: str | Path, top_n: int = 20) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    top = frame.sort_values("importance", ascending=False).head(top_n).sort_values("importance")
    figure, axis = plt.subplots(figsize=(9, 7))
    axis.barh(top["feature"], top["importance"], color="#237a8b")
    axis.set(title=f"Top {top_n} LightGBM Feature Importances", xlabel="Gain importance", ylabel="Feature")
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)

