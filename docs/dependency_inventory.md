# Dependency Inventory

Machine-readable inventory of third-party components used or referenced by the
public repository. Versions are taken from the verification environment
(2026-09-20) and from the build files in this repository. License conclusions and
evidence are recorded in `docs/licensing_review.md` and
`THIRD_PARTY_NOTICES.md`.

## A. Direct runtime dependencies (Python)

Source: `pyproject.toml`, `requirements.txt`.

| Package | Version (verified env) | License | Evidence |
| --- | --- | --- | --- |
| pandas | 3.0.6 | BSD-3-Clause | upstream LICENSE, package metadata |
| numpy | 2.4.6 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | package metadata |
| scikit-learn | 1.9.1 | BSD-3-Clause | package metadata |
| lightgbm | 4.7.0 | MIT | upstream LICENSE, package metadata |
| matplotlib | 3.11.2 | Matplotlib license (PSF-based) | upstream LICENSE, package metadata classifier |
| tldextract | 5.3.2 | BSD-3-Clause | upstream LICENSE, package metadata |
| PyYAML | 6.0.3 | MIT | upstream LICENSE, package metadata |
| joblib | 1.6.0 | BSD-3-Clause | upstream LICENSE, package metadata |
| certifi | 2026.7.22 | MPL-2.0 | upstream LICENSE, package metadata |

## B. Optional / build-time dependencies (Python)

Source: `pyproject.toml` optional groups.

| Package | Version (verified env) | Group | License | Evidence |
| --- | --- | --- | --- | --- |
| pytest | 9.1.1 | `dev` | MIT | package metadata |
| torch | 2.14.0 | `urlbert` (training only) | BSD-3-Clause core; wheel lists Apache-2.0 / LLVM-exception / BSD-2-Clause / BSL-1.0 / MIT components | upstream LICENSE, package metadata |
| transformers | 5.17.0 | `urlbert` | Apache-2.0 | upstream LICENSE, package metadata |
| safetensors | 0.8.0 | `urlbert` | Apache-2.0 | upstream classifier, package metadata |
| onnx | 1.23.0 | `deployment` | Apache-2.0 | package metadata |
| onnxruntime | 1.30.0 | `deployment` | MIT | upstream LICENSE, package metadata |
| onnxscript | 0.7.2 | `deployment` | MIT | upstream LICENSE, package metadata |
| setuptools | build backend | `build-system` | MIT | package metadata (not redistributed) |

## C. Datasets

Source: `data/processed/**/*.json`, `data/README.md`, `configs/`.

| Dataset | Role | License | Redistributed | Status |
| --- | --- | --- | --- | --- |
| Tranco | BENIGN seed domains | not stated by upstream | no | NEEDS_REVIEW |
| OpenPhish Community Feed | PHISHING rows | Terms of Use (no open license found) | no | NEEDS_REVIEW |
| CERT Polska Warning List | PHISHING rows | not found on official page | no | NEEDS_REVIEW |
| Phishing.Database | PHISHING rows | MIT (GitHub license metadata) | no | PASS |
| URLhaus | Threat intelligence | fair-use terms (abuse.ch) | no (digests only) | NEEDS_REVIEW |
| ThreatFox | Threat intelligence | fair-use terms (abuse.ch) | no (digests only) | NEEDS_REVIEW |
| Common Crawl | Optional `FULL_URL` candidates | not verified | no | NEEDS_REVIEW |

## D. Models

Source: `models/**/metadata.json`, `deployment/android/v*/deployment_manifest.json`.

| Model | Version | Base / origin | License | Redistributed |
| --- | --- | --- | --- | --- |
| URLBERT base encoder | revision `0207444` | `CrabInHoney/urlbert-tiny-v6` | Apache-2.0 | derivative ONNX yes; PyTorch checkpoints no |
| URLBERT binary (`URLBERT_PHISHING_BINARY_V1`) | 0.6.0 | fine-tuned from base | Apache-2.0 (derivative) | ONNX yes |
| LightGBM binary (`LIGHTGBM_PHISHING_BINARY_V1`) | model 0.6.0 family | trained in this project | project Apache-2.0 | `model.txt` yes |
| LightGBM V2 / no-IP | 0.5.0 family | trained in this project | project Apache-2.0 | metadata only |
| UGDM | architecture `UGDM-v1` | trained in this project | project Apache-2.0 | metadata only |

## E. Embedded data / assets

Source: `deployment/`.

| Asset | Origin | License | Redistributed |
| --- | --- | --- | --- |
| `public_suffixes.txt` (v1, v2) | Public Suffix List via tldextract snapshot | MPL-2.0 | yes (`licenses/MPL-2.0.txt`) |
| `tokenizer.json` (v1, v2) | derived from base model tokenizer | Apache-2.0 | yes |
| `threat_intel_sha256.txt`, `ti_bundle.json`, UGDM `threat_intel_snapshot.json` | URLhaus / ThreatFox snapshots | source terms apply; digests only | yes (hashes only) |
| `golden_set.json`, `policy_v2_golden.json` | generated synthetic fixtures | project Apache-2.0 | yes |
| `adversarial_urls_v1.json` | generated synthetic corpus | project Apache-2.0 | yes |
| `deployment/android/v*/deployment_manifest.json` | project records | project Apache-2.0 | yes |

## F. Referenced but not redistributed

- Raw and processed datasets (phishing / malware URLs).
- URLBERT PyTorch checkpoints (`models/urlbert*/**/*.pt`), UGDM `model.pt`.
- Production-signed APK / AAB, production keystore, signing material.
- Android Gradle Plugin artifacts and Gradle distributions (resolved at build time).

## Android dependency set

Source: `android/app/build.gradle.kts`, `android/build.gradle.kts`, `android/gradle/wrapper/gradle-wrapper.properties`.

| Component | Version | License | Redistributed |
| --- | --- | --- | --- |
| Gradle wrapper (`gradle-wrapper.jar`) | 8.13 | Apache-2.0 | yes (wrapper binary) |
| Android Gradle Plugin | 8.13.2 | not declared in POM/jar metadata | no | 
| Kotlin / Compose compiler plugin | 2.2.21 | Apache-2.0 | no |
| Compose BOM / material3 / ui / activity-compose | 2024.09.03 / 1.9.2 | Apache-2.0 | no |
| ONNX Runtime Android | 1.30.0 | MIT | no |
| org.json | 20250517 | Public Domain | no |
| JUnit 4 | 4.13.2 | EPL-1.0 | no |
| androidx.test (runner / core / ext-junit) | 1.6.2 / 1.6.1 / 1.2.1 | Apache-2.0 | no |
