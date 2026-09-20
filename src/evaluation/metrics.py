from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize

LABEL_NAMES = ["BENIGN", "PHISHING", "MALWARE"]
BINARY_LABEL_NAMES = ["BENIGN", "PHISHING"]


def calculate_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, probabilities: np.ndarray | None = None
) -> dict[str, Any]:
    macro = precision_recall_fscore_support(y_true, y_pred, labels=[0, 1, 2], average="macro", zero_division=0)
    weighted = precision_recall_fscore_support(y_true, y_pred, labels=[0, 1, 2], average="weighted", zero_division=0)
    report = classification_report(
        y_true, y_pred, labels=[0, 1, 2], target_names=LABEL_NAMES, output_dict=True, zero_division=0
    )
    benign = y_true == 0
    malicious = y_true != 0
    benign_fpr = float(np.mean(y_pred[benign] != 0)) if benign.any() else 0.0
    malicious_fnr = float(np.mean(y_pred[malicious] == 0)) if malicious.any() else 0.0
    output = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "weighted_f1": float(weighted[2]),
        "phishing_recall": float(report["PHISHING"]["recall"]),
        "malware_recall": float(report["MALWARE"]["recall"]),
        "benign_false_positive_rate": benign_fpr,
        "malicious_false_negative_rate": malicious_fnr,
        "per_class": {name: report[name] for name in LABEL_NAMES},
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1, 2]).tolist(),
    }
    if probabilities is not None:
        binary = label_binarize(y_true, classes=[0, 1, 2])
        output["auroc_ovr_macro"] = float(
            roc_auc_score(binary, probabilities, average="macro", multi_class="ovr")
        )
        output["auprc_ovr_macro"] = float(average_precision_score(binary, probabilities, average="macro"))
    else:
        output["auroc_ovr_macro"] = None
        output["auprc_ovr_macro"] = None
    return output


def calculate_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    probabilities: np.ndarray | None = None,
) -> dict[str, Any]:
    """Binary BENIGN(0) / PHISHING(1) metrics.

    Phishing is the positive class. `specificity` is BENIGN recall, and
    `false_positive_rate` is the benign FPR that a product would experience.
    """

    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    report = classification_report(
        y_true, y_pred, labels=[0, 1], target_names=BINARY_LABEL_NAMES, output_dict=True, zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(matrix[0, 0]),
        int(matrix[0, 1]),
        int(matrix[1, 0]),
        int(matrix[1, 1]),
    )
    benign_total = true_negative + false_positive
    phishing_total = true_positive + false_negative
    specificity = true_negative / benign_total if benign_total else 0.0
    false_positive_rate = false_positive / benign_total if benign_total else 0.0
    false_negative_rate = false_negative / phishing_total if phishing_total else 0.0
    output: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(report["PHISHING"]["precision"]),
        "recall": float(report["PHISHING"]["recall"]),
        "f1": float(report["PHISHING"]["f1-score"]),
        "specificity": float(specificity),
        "false_positive_rate": float(false_positive_rate),
        "false_negative_rate": float(false_negative_rate),
        "balanced_accuracy": float((float(report["PHISHING"]["recall"]) + specificity) / 2.0),
        "truePositive": true_positive,
        "trueNegative": true_negative,
        "falsePositive": false_positive,
        "falseNegative": false_negative,
        "benignSupport": int(benign_total),
        "phishingSupport": int(phishing_total),
        "per_class": {name: report[name] for name in BINARY_LABEL_NAMES},
        "confusion_matrix": matrix.tolist(),
    }
    if probabilities is not None:
        probabilities = np.asarray(probabilities)
        positive = probabilities[:, 1]
        if np.unique(y_true).size < 2:
            # A single-class slice (for example a source subgroup) has no defined
            # ranking metric. Report None instead of a fabricated number.
            output["auroc"] = None
            output["auprc"] = None
        else:
            output["auroc"] = float(roc_auc_score(y_true, positive))
            output["auprc"] = float(average_precision_score(y_true, positive))
    else:
        output["auroc"] = None
        output["auprc"] = None
    return output
