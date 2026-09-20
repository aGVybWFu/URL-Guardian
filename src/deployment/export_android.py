"""Export the frozen binary URLBERT pipeline for Android.

The exporter is deliberately offline with respect to analysed URLs. It reads the
already trained checkpoint and frozen local threat-intelligence snapshot, writes
versioned assets, and proves PyTorch/ONNX parity on safe reserved-domain fixtures.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import sys
from pathlib import Path
from typing import Any

import numpy as np

from src.data.normalizer import normalize_url
from src.deployment import DEPLOYMENT_VERSION
from src.features.extractor import extract_features
from src.ugdm.features import default_availability, feature_spec_payload
from src.ugdm.policy import PolicyThresholds, decide
from src.ugdm.schema import UGDMOutputSchema

ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = ROOT / "models" / "urlbert_binary" / "v1"
SNAPSHOT = ROOT / "data" / "processed" / "ugdm-v1.0.0" / "threat_intel_snapshot.json"
OUTPUT = ROOT / "deployment" / "android" / "v1"
MAX_LENGTH = 32
POLICY_THRESHOLDS = PolicyThresholds(review_at=0.35, block_at=0.85)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fixtures() -> list[str]:
    bases = [
        "https://example.com/", "http://example.org/docs", "example.net/help",
        "https://www.example.com/account", "https://shop.example.org/payment",
        "https://support.example.net/verify", "https://login.example.com/session",
        "https://secure.example.org/update", "https://example.com/wallet",
        "https://example.net/password/reset", "https://a.b.c.example.com/path",
        "https://xn--r8jz45g.xn--zckzah/", "http://192.0.2.10/test",
        "https://[2001:db8::1]:8443/demo", "https://example.com:4443/portal",
        "https://user@example.com/profile", "https://example.com/a-b-c",
        "https://12345.example.net/67890", "https://example.org/%2Fsafe?q=%AA",
        "https://example.com/path?token=REDACTED", "https://example.net/#section",
        " HTTPS://EXAMPLE.COM./MixedCase ", "https://例え.テスト/安全",
        "https://sub.example.co.uk/guide", "https://sub.example.com.tw/guide",
        "https://example.com/" + "a" * 180, "https://example.org/a_b_c",
        "https://example.net/a.b.c", "https://example.com/signin",
        "https://example.org/confirmation", "https://example.net/oauth/callback",
        "https://example.com/bank/info", "http://example.org:80/default",
        "https://example.net:443/default", "https://0.example.com/",
        "https://hyphen-name.example.org/", "https://many.dots.in.example.net/",
        "https://example.com/?a=1&b=2&c=3", "https://example.org/%41%42%43",
        "https://example.net/trailing/", "https://localhost.example/test",
        "https://dev.example.com:8080/", "https://example.com/@symbol",
        "https://example.org/login/verify/account", "https://example.net/pay-ment",
        "http://198.51.100.24:8080/login", "https://203.0.113.9/",
        "https://[2001:db8:1::5]/", "https://xn--e1afmkfd.xn--p1ai/",
        "https://example.com/a%20space", "https://example.org/?next=https%3A%2F%2Fexample.net",
        "https://example.net/?q=000000", "https://a.example.com/secure",
        "https://b.example.org/verify", "https://c.example.net/account",
        "https://example.com/no-risk-words", "https://example.org/index.html",
        "https://example.net/api/v1/resource", "https://example.com/download/file.zip",
        "https://example.org/news/2026/09/20", "https://example.net/search?q=safe",
        "https://example.com/~user", "https://example.org/plus+sign",
        "https://example.net/semicolon;value", "https://example.com/comma,value",
    ]
    if len(bases) < 50:
        raise AssertionError("deployment golden set must contain at least 50 fixtures")
    return bases


def _load_model_and_tokenizer():
    import torch
    from transformers import AutoTokenizer

    from src.models.urlbert.model import load_checkpoint

    metadata = json.loads((MODEL_DIR / "metadata.json").read_text(encoding="utf-8"))
    name = str(metadata["baseModel"])
    revision = str(metadata["baseModelRevision"])
    model, _ = load_checkpoint(MODEL_DIR / "best.pt", name, revision)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR / "best_tokenizer", local_files_only=True)
    model.cpu().eval()
    return torch, model, tokenizer, metadata


def _write_public_suffixes(path: Path) -> int:
    import tldextract

    extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    suffixes: set[str] = set()
    for item in extractor.tlds:
        rule = str(item).lower()
        if not rule:
            continue
        suffixes.add(rule)
        prefix = "!" if rule.startswith("!") else "*." if rule.startswith("*.") else ""
        body = rule[len(prefix):]
        try:
            suffixes.add(prefix + ".".join(label.encode("idna").decode("ascii") for label in body.split(".")))
        except UnicodeError:
            pass
    suffixes = sorted(suffixes)
    path.write_text("\n".join(suffixes) + "\n", encoding="utf-8", newline="\n")
    return len(suffixes)


def _write_threat_intel(path: Path) -> dict[str, Any]:
    payload = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    digests = sorted(set(payload["indicatorDigests"]))
    if len(digests) != int(payload["indicatorCount"]):
        raise RuntimeError("frozen TI snapshot count mismatch")
    path.write_text("\n".join(digests) + "\n", encoding="ascii", newline="\n")
    return {
        "snapshotFileSHA256": sha256_file(SNAPSHOT),
        "indicatorCount": len(digests),
        "assetSHA256": sha256_file(path),
        "providers": payload.get("providers", []),
    }


def export(output: Path = OUTPUT) -> dict[str, Any]:
    import onnx
    import onnxruntime as ort

    torch, model, tokenizer, metadata = _load_model_and_tokenizer()
    output.mkdir(parents=True, exist_ok=True)
    tokenizer_source = MODEL_DIR / "best_tokenizer" / "tokenizer.json"
    tokenizer_target = output / "tokenizer.json"
    shutil.copyfile(tokenizer_source, tokenizer_target)
    psl_count = _write_public_suffixes(output / "public_suffixes.txt")
    ti = _write_threat_intel(output / "threat_intel_sha256.txt")

    fixture_rows: list[dict[str, Any]] = []
    encoded_rows: list[dict[str, Any]] = []
    for raw in _fixtures():
        normalized = normalize_url(raw)
        encoded = tokenizer(
            normalized.registrable_domain,
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
        )
        encoded_rows.append(encoded)
        selected_features = extract_features(normalized)
        fixture_rows.append({
            "input": raw,
            "normalizedUrl": normalized.normalized_url,
            "hostname": normalized.hostname,
            "registrableDomain": normalized.registrable_domain,
            "tokenIds": encoded["input_ids"],
            "attentionMask": encoded["attention_mask"],
            "features": selected_features,
        })

    input_ids = torch.tensor([row["input_ids"] for row in encoded_rows], dtype=torch.long)
    attention_mask = torch.tensor([row["attention_mask"] for row in encoded_rows], dtype=torch.long)
    onnx_path = output / "urlbert_binary.onnx"
    with torch.no_grad():
        torch_logits = model(input_ids, attention_mask).detach().cpu().numpy().astype(np.float32)
    torch.onnx.export(
        model,
        (input_ids[:2], attention_mask[:2]),
        onnx_path,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch"}, "attention_mask": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=18,
        dynamo=True,
        external_data=False,
    )
    onnx.checker.check_model(onnx.load(onnx_path))
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_logits = session.run(None, {
        "input_ids": input_ids.numpy().astype(np.int64),
        "attention_mask": attention_mask.numpy().astype(np.int64),
    })[0].astype(np.float32)

    def softmax(values: np.ndarray) -> np.ndarray:
        shifted = values - values.max(axis=1, keepdims=True)
        exp = np.exp(shifted)
        return exp / exp.sum(axis=1, keepdims=True)

    torch_probs = softmax(torch_logits)
    onnx_probs = softmax(onnx_logits)
    logit_error = np.abs(torch_logits - onnx_logits)
    probability_error = np.abs(torch_probs - onnx_probs)
    class_agreement = np.argmax(torch_probs, axis=1) == np.argmax(onnx_probs, axis=1)
    parity = {
        "fixtureCount": len(fixture_rows),
        "logitMaxAbsoluteError": float(logit_error.max()),
        "logitMeanAbsoluteError": float(logit_error.mean()),
        "probabilityMaxAbsoluteError": float(probability_error.max()),
        "probabilityMeanAbsoluteError": float(probability_error.mean()),
        "classAgreement": float(class_agreement.mean()),
        "requiredClassAgreement": 1.0,
        "passed": bool(class_agreement.all()),
        "providers": session.get_providers(),
    }
    if not parity["passed"]:
        raise RuntimeError("PyTorch/ONNX class parity failed")

    availability = default_availability({"URLHAUS": "AVAILABLE", "THREATFOX": "AVAILABLE"})
    for index, row in enumerate(fixture_rows):
        probability = float(onnx_probs[index, 1])
        extracted = row["features"]
        features = {
            "phishing_probability": probability,
            "known_malicious": 0.0,
            "url_length": float(extracted["url_length"]),
            "hostname_length": float(extracted["hostname_length"]),
            "subdomain_count": float(extracted["subdomain_count"]),
            "digit_ratio": float(extracted["digit_ratio"]),
            "special_character_ratio": float(extracted["special_character_ratio"]),
            "hostname_entropy": float(extracted["hostname_entropy"]),
            "has_ip": float(extracted["has_ip_address"]),
            "has_punycode": float(extracted["has_punycode"]),
            "has_at_symbol": float(extracted["has_at_symbol"]),
            "uses_https": float(extracted["is_https"]),
            "has_non_default_port": float(extracted["has_non_default_port"]),
            **{name: float(extracted[name]) for name in (
                "contains_login", "contains_verify", "contains_secure", "contains_account",
                "contains_password", "contains_payment", "contains_wallet",
            )},
        }
        decision = decide(features, availability, POLICY_THRESHOLDS)
        row["pytorchLogits"] = [float(v) for v in torch_logits[index]]
        row["onnxLogits"] = [float(v) for v in onnx_logits[index]]
        row["onnxProbabilities"] = [float(v) for v in onnx_probs[index]]
        row["expectedRisk"] = decision.risk
        row["expectedAction"] = decision.action
        row["expectedReason"] = decision.reason

    (output / "golden_set.json").write_text(
        json.dumps({"schemaVersion": 1, "maxLength": MAX_LENGTH, "fixtures": fixture_rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output / "parity_report.json").write_text(json.dumps(parity, indent=2), encoding="utf-8")
    (output / "feature_schema.json").write_text(
        json.dumps(feature_spec_payload(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output / "output_schema.json").write_text(
        json.dumps(UGDMOutputSchema().to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    policy = {
        "policyVersion": "DecisionPolicyV1",
        "costVersion": "DecisionCostV1",
        "reviewAt": POLICY_THRESHOLDS.review_at,
        "blockAt": POLICY_THRESHOLDS.block_at,
        "probabilityVersion": "uncalibrated",
        "knownMaliciousGuardrail": "always_block",
        "ugdmEnabled": False,
    }
    (output / "decision_policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")
    assets = [
        "urlbert_binary.onnx", "tokenizer.json", "public_suffixes.txt",
        "threat_intel_sha256.txt", "golden_set.json", "parity_report.json",
        "feature_schema.json", "output_schema.json", "decision_policy.json",
    ]
    manifest = {
        "schemaVersion": 1,
        "deploymentVersion": DEPLOYMENT_VERSION,
        "appVersion": "0.8.0",
        "app": {
            "applicationId": "org.urlguardian.app",
            "versionName": "0.8.0",
            "minSdk": 26,
            "targetSdk": 35,
            "compileSdk": 35,
            "abis": ["arm64-v8a", "x86_64"],
            "runtime": "onnxruntime-android:1.30.0 CPU",
            "defaultDecisionEngine": "DecisionPolicyV1",
        },
        "model": {
            "name": metadata.get("modelName"),
            "experimentId": metadata.get("experimentId"),
            "version": metadata.get("modelVersion"),
            "baseModel": metadata.get("baseModel"),
            "revision": metadata.get("baseModelRevision"),
            "checkpointSHA256": sha256_file(MODEL_DIR / "best.pt"),
            "onnxSHA256": sha256_file(onnx_path),
            "maxLength": MAX_LENGTH,
            "labels": metadata.get("labelMapping"),
        },
        "tokenizer": {
            "class": metadata.get("tokenizer", {}).get("class", "TokenizersBackend"),
            "vocabularySize": metadata.get("tokenizer", {}).get("vocabularySize", 8192),
            "sha256": sha256_file(tokenizer_target),
        },
        "threatIntelligence": ti,
        "policy": policy,
        "ugdm": {"enabled": False, "status": "experimental_only", "version": "0.7.0"},
        "schemas": {"feature": 1, "output": 1},
        "publicSuffixCount": psl_count,
        "goldenFixtureCount": len(fixture_rows),
        "parity": parity,
        "assets": {name: sha256_file(output / name) for name in assets},
    }
    (output / "deployment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    manifest = export()
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
