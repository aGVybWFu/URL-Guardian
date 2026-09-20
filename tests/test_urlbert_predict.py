"""URLBERT prediction CLI tests."""

import json
from pathlib import Path

import pytest

from src.models.urlbert.config import load_urlbert_config
from src.models.urlbert.model import CheckpointInfo, URLBertClassifier, save_checkpoint


class _StubTokenizer:
    """Minimal tokenizer stand-in so prediction tests stay offline and fast."""

    def __call__(self, text, **kwargs):
        import torch

        if isinstance(text, str):
            text = [text]
        length = max(1, min(8, len(text[0])))
        input_ids = torch.ones((len(text), length), dtype=torch.long)
        attention_mask = torch.ones_like(input_ids)
        return {"input_ids": input_ids, "attention_mask": attention_mask}

    def save_pretrained(self, directory):
        Path(directory).mkdir(parents=True, exist_ok=True)
        (Path(directory) / "tokenizer_config.json").write_text("{}", encoding="utf-8")


@pytest.fixture()
def trained_stub_checkpoint(frozen_dataset_factory, tiny_encoder, monkeypatch):
    fixture = frozen_dataset_factory()
    config = load_urlbert_config(fixture["config_path"])
    model = URLBertClassifier(tiny_encoder, hidden_size=config.head_hidden_size, dropout=0.0)
    save_checkpoint(
        config.path("checkpoint_dir"),
        "best",
        model,
        _StubTokenizer(),
        CheckpointInfo(experiment_id="TEST", epoch=1, validation_macro_f1=0.5),
    )
    metadata = {
        "modelName": "url_guardian_urlbert",
        "modelVersion": "0.4.0",
        "experimentId": "URLBERT_DOMAIN_ONLY_V1_TEST",
        "datasetVersion": config.dataset_version,
        "probabilityStatus": "UNCALIBRATED PROBABILITY",
    }
    (config.path("checkpoint_dir") / "metadata.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )

    def fake_runtime(urlbert_config):
        import torch

        stub = URLBertClassifier(tiny_encoder, hidden_size=urlbert_config.head_hidden_size, dropout=0.0)
        return stub, _StubTokenizer(), metadata, torch.device("cpu")

    monkeypatch.setattr("src.models.urlbert.predict._load_runtime", fake_runtime)
    return fixture


def test_predict_cli_reports_probabilities_and_model_version(trained_stub_checkpoint):
    from src.models.urlbert.predict import predict_text

    result = predict_text("https://login-verify.example.com/path?x=1", trained_stub_checkpoint["config_path"])
    assert result["resultType"] == "Model Prediction"
    assert result["registrableDomain"] == "example.com"
    assert set(result["probabilities"]) == {"BENIGN", "PHISHING", "MALWARE"}
    assert abs(sum(result["probabilities"].values()) - 1.0) < 1e-6
    assert result["predictedClass"] in {"BENIGN", "PHISHING", "MALWARE"}
    assert result["modelVersion"] == "0.4.0"
    assert result["probabilityStatus"] == "UNCALIBRATED PROBABILITY"


def test_predict_cli_uses_the_domain_only_reduction(trained_stub_checkpoint):
    from src.models.urlbert.predict import predict_text

    result = predict_text("https://www.sub.deep.example.co.uk/a/b", trained_stub_checkpoint["config_path"])
    assert result["registrableDomain"] == "example.co.uk"
    assert result["normalizedUrl"] == "https://www.sub.deep.example.co.uk/a/b"


def test_predict_cli_refuses_a_raw_malicious_url_request(trained_stub_checkpoint):
    """The CLI must only parse strings; no network-capable client is imported."""

    source = (
        Path(__file__).resolve().parents[1] / "src" / "models" / "urlbert" / "predict.py"
    ).read_text(encoding="utf-8")
    for token in ("requests.get(", "requests.post(", "socket.connect(", "getaddrinfo(", "urlopen("):
        assert token not in source


def test_predict_cli_reports_missing_checkpoint(tmp_path, frozen_dataset_factory):
    from src.models.urlbert.predict import predict_text

    fixture = frozen_dataset_factory()
    with pytest.raises(FileNotFoundError, match="No trained URLBERT checkpoint"):
        predict_text("example.com", fixture["config_path"])
