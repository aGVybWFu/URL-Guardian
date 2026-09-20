"""Forward-pass and architecture tests for the URLBERT classifier head."""

import pytest
import torch

from src.models.urlbert.model import NUM_CLASSES, URLBertClassifier, load_encoder

REAL_BASE_MODEL = "CrabInHoney/urlbert-tiny-v6"
REAL_REVISION = "020744435b3be870dabb2bba0b41237bea69b84b"


def _classifier(tiny_encoder):
    return URLBertClassifier(tiny_encoder, hidden_size=16, dropout=0.0)


def test_forward_returns_three_class_logits(tiny_encoder):
    model = _classifier(tiny_encoder)
    input_ids = torch.randint(0, 256, (4, 12))
    attention_mask = torch.ones_like(input_ids)
    logits = model(input_ids, attention_mask)
    assert logits.shape == (4, NUM_CLASSES)


def test_pooling_concatenates_cls_and_masked_mean(tiny_encoder):
    model = _classifier(tiny_encoder)
    input_ids = torch.randint(0, 256, (2, 8))
    attention_mask = torch.ones_like(input_ids)
    with torch.no_grad():
        hidden = model.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        pooled = model.pool(hidden, attention_mask)
    assert pooled.shape == (2, hidden.shape[-1] * 2)
    assert torch.allclose(pooled[:, : hidden.shape[-1]], hidden[:, 0, :], atol=1e-5)
    expected_mean = hidden.mean(dim=1)
    assert torch.allclose(pooled[:, hidden.shape[-1] :], expected_mean, atol=1e-5)


def test_padding_tokens_do_not_change_the_pooled_mean(tiny_encoder):
    model = _classifier(tiny_encoder)
    content = torch.randint(4, 256, (1, 6))
    padded_ids = torch.cat([content, torch.full((1, 4), 3, dtype=torch.long)], dim=1)
    content_mask = torch.ones_like(content)
    padded_mask = torch.cat([content_mask, torch.zeros((1, 4), dtype=torch.long)], dim=1)
    with torch.no_grad():
        short = model.pool(
            model.encoder(input_ids=content, attention_mask=content_mask).last_hidden_state, content_mask
        )
        long = model.pool(
            model.encoder(input_ids=padded_ids, attention_mask=padded_mask).last_hidden_state, padded_mask
        )
    assert torch.allclose(short, long, atol=1e-5)


def test_head_is_newly_initialized_and_trainable(tiny_encoder):
    model = _classifier(tiny_encoder)
    assert model.classifier[0].out_features == 16
    assert model.classifier[-1].out_features == NUM_CLASSES
    assert model.trainable_parameters() == model.total_parameters()
    assert model.trainable_parameters() > 0


def test_batch_size_one_matches_batched_logits(tiny_encoder):
    model = _classifier(tiny_encoder)
    model.eval()
    input_ids = torch.randint(0, 256, (3, 10))
    attention_mask = torch.ones_like(input_ids)
    with torch.no_grad():
        batched = model(input_ids, attention_mask)
        single = torch.cat(
            [model(input_ids[index : index + 1], attention_mask[index : index + 1]) for index in range(3)],
            dim=0,
        )
    assert torch.allclose(batched, single, atol=1e-5)


def test_real_pretrained_encoder_loads_and_forwards():
    """Confirm the pinned upstream encoder is still compatible with this project."""

    pytest.importorskip("transformers")
    try:
        encoder, spec = load_encoder(REAL_BASE_MODEL, REAL_REVISION)
    except Exception:  # pragma: no cover - environment dependent
        pytest.skip("Pinned URLBERT encoder is not available in this environment")
    assert spec.architecture == "ModernBertModel"
    assert spec.hidden_size == 128
    assert spec.params == 2_033_408
    model = URLBertClassifier(encoder, hidden_size=32, dropout=0.0)
    model.eval()
    input_ids = torch.randint(4, spec.vocab_size, (2, 16))
    attention_mask = torch.ones_like(input_ids)
    with torch.no_grad():
        logits = model(input_ids, attention_mask)
    assert logits.shape == (2, NUM_CLASSES)
