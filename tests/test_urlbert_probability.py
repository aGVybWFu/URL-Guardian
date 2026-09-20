"""Probability semantics tests: pipeline output must be softmax, not logits."""

import numpy as np
import torch

from src.evaluation.metrics import calculate_metrics
from src.models.urlbert.model import NUM_CLASSES, URLBertClassifier


def test_probabilities_are_softmax_not_logits(tiny_encoder):
    model = URLBertClassifier(tiny_encoder, hidden_size=16, dropout=0.0)
    model.eval()
    input_ids = torch.randint(0, 256, (5, 9))
    attention_mask = torch.ones_like(input_ids)
    with torch.no_grad():
        logits = model(input_ids, attention_mask)
        probabilities = model.probabilities(input_ids, attention_mask)
    assert torch.allclose(torch.softmax(logits, dim=-1), probabilities, atol=1e-6)
    if int(logits.abs().max() * 1000) != 0:
        assert not torch.allclose(logits, probabilities, atol=1e-3)


def test_probabilities_form_a_distribution(tiny_encoder):
    model = URLBertClassifier(tiny_encoder, hidden_size=16, dropout=0.0)
    model.eval()
    input_ids = torch.randint(0, 256, (7, 5))
    attention_mask = torch.ones_like(input_ids)
    with torch.no_grad():
        probabilities = model.probabilities(input_ids, attention_mask).numpy()
    assert probabilities.shape == (7, NUM_CLASSES)
    assert np.all(probabilities >= 0.0)
    assert np.all(probabilities <= 1.0)
    assert np.allclose(probabilities.sum(axis=1), 1.0, atol=1e-6)


def test_softmax_probabilities_drive_auroc_and_auprc():
    y_true = np.array([0, 0, 1, 1, 2, 2])
    y_pred = np.array([0, 1, 1, 1, 2, 0])
    probabilities = np.array(
        [
            [0.7, 0.2, 0.1],
            [0.4, 0.5, 0.1],
            [0.2, 0.7, 0.1],
            [0.3, 0.6, 0.1],
            [0.1, 0.2, 0.7],
            [0.5, 0.3, 0.2],
        ]
    )
    metrics = calculate_metrics(y_true, y_pred, probabilities)
    assert metrics["auroc_ovr_macro"] is not None
    assert metrics["auprc_ovr_macro"] is not None
    assert 0.0 <= metrics["auroc_ovr_macro"] <= 1.0
    assert 0.0 <= metrics["auprc_ovr_macro"] <= 1.0
    assert 0.0 <= metrics["benign_false_positive_rate"] <= 1.0
    assert 0.0 <= metrics["malicious_false_negative_rate"] <= 1.0


def test_training_metadata_declares_uncalibrated_probability():
    import json

    from src.models.urlbert.config import load_urlbert_config

    config = load_urlbert_config()
    metadata_path = config.path("checkpoint_dir") / "metadata.json"
    if not metadata_path.exists():
        import pytest

        pytest.skip("Official URLBERT checkpoint metadata is not available in this environment")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["probabilityStatus"] == "UNCALIBRATED PROBABILITY"
    assert metadata["testMetrics"]["probabilityStatus"] == "UNCALIBRATED PROBABILITY"
