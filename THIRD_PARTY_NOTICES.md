# Third-Party Notices

URL Guardian uses or references third-party software, models, datasets, and data
resources. This file records what was verified for the public 1.0.0 release and
what is redistributed in this repository.

Evidence sources used: upstream LICENSE files, upstream repository metadata,
Hugging Face model metadata, Maven POM metadata, and installed package metadata.
Items that could not be verified from an authoritative source are marked
`NEEDS_REVIEW`.

## Software

### ONNX Runtime

- Upstream: https://github.com/microsoft/onnxruntime
- Version: 1.30.0 (`onnxruntime` for desktop export checks; `com.microsoft.onnxruntime:onnxruntime-android` in the app)
- License: MIT
- Evidence: Maven POM `onnxruntime-android-1.30.0.pom`; upstream LICENSE; PyPI package metadata (`License: MIT License`)
- Usage: local ONNX inference in research runs and on-device inference in the Android app.
- Redistribution: not bundled in this repository; resolved as a Gradle/Maven dependency at build time.

### Hugging Face Transformers

- Upstream: https://github.com/huggingface/transformers
- Version: 5.17.0 (verification environment)
- License: Apache-2.0
- Evidence: upstream LICENSE; package metadata (`License: Apache 2.0 License`)
- Usage: loads the base encoder and tokenizer for fine-tuning, evaluation and ONNX export.
- Redistribution: not bundled.

### PyTorch

- Upstream: https://github.com/pytorch/pytorch
- Version: 2.14.0 (verification environment)
- License: BSD-3-Clause for the PyTorch core (upstream LICENSE). The installed wheel also lists bundled components under Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSL-1.0 and MIT.
- Evidence: upstream LICENSE; package metadata (`License-Expression`)
- Usage: training, evaluation and ONNX export only. The Android app does not ship or load PyTorch.
- Redistribution: not bundled.

### LightGBM

- Upstream: https://github.com/microsoft/LightGBM
- Version: 4.7.0 (verification environment)
- License: MIT
- Evidence: upstream LICENSE; package metadata (`License: MIT`)
- Usage: baseline model training and evaluation.
- Redistribution: not bundled.

### pandas / NumPy / scikit-learn / joblib

- Upstreams: https://github.com/pandas-dev/pandas, https://github.com/numpy/numpy, https://github.com/scikit-learn/scikit-learn, https://github.com/joblib/joblib
- Versions: pandas 3.0.6, NumPy 2.4.6, scikit-learn 1.9.1, joblib 1.6.0 (verification environment)
- License: BSD-3-Clause for all four. NumPy package metadata additionally lists `0BSD`, `MIT`, `Zlib` and `CC0-1.0` for bundled components.
- Evidence: upstream LICENSE files; package metadata
- Usage: data processing, metrics and experiment pipelines.
- Redistribution: not bundled.

### tldextract

- Upstream: https://github.com/john-kurkowski/tldextract
- Version: 5.3.2 (verification environment)
- License: BSD-3-Clause
- Evidence: upstream LICENSE; package metadata
- Usage: registrable-domain parsing with the bundled Public Suffix List snapshot, offline.
- Redistribution: not bundled; the exported suffix list is covered under Data Resources below.

### Matplotlib

- Upstream: https://github.com/matplotlib/matplotlib
- Version: 3.11.2 (verification environment)
- License: Matplotlib license (PSF-based, BSD-compatible)
- Evidence: upstream `LICENSE/LICENSE`; package metadata classifier `License :: OSI Approved :: Python Software Foundation License`
- Usage: report figures only.
- Redistribution: not bundled.

### PyYAML

- Upstream: https://github.com/yaml/pyyaml
- Version: 6.0.3 (verification environment)
- License: MIT
- Evidence: upstream LICENSE; package metadata
- Usage: config parsing.
- Redistribution: not bundled.

### certifi

- Upstream: https://github.com/certifi/python-certifi
- Version: 2026.7.22 (verification environment)
- License: MPL-2.0
- Evidence: upstream LICENSE; package metadata (`License-Expression: MPL-2.0`)
- Usage: CA bundle for approved source-acquisition HTTPS requests.
- Redistribution: not bundled.

### pytest

- Upstream: https://github.com/pytest-dev/pytest
- Version: 9.1.1 (verification environment)
- License: MIT
- Usage: test runner.
- Redistribution: not bundled.

### ONNX / onnxscript / safetensors

- Upstreams: https://github.com/onnx/onnx, https://github.com/microsoft/onnxscript, https://github.com/huggingface/safetensors
- Versions: onnx 1.23.0, onnxscript 0.7.2, safetensors 0.8.0 (verification environment)
- Licenses: Apache-2.0, MIT, Apache-2.0
- Usage: model export and checkpoint handling.
- Redistribution: not bundled.

### org.json

- Upstream: https://github.com/stleary/JSON-java
- Version: 20250517
- License: Public Domain
- Evidence: Maven POM `<licenses>` (`Public Domain`); upstream LICENSE (first line: `Public Domain.`)
- Usage: JSON parsing in the Android app.
- Redistribution: resolved as a Gradle dependency; not vendored into this repository.

### Kotlin, Jetpack Compose, AndroidX

- Upstreams: https://github.com/JetBrains/kotlin, https://github.com/androidx/androidx
- Versions: Kotlin 2.2.21, Compose BOM 2024.09.03, activity-compose 1.9.2, androidx.test 1.2.1 / 1.6.2 / 1.6.1
- License: Apache-2.0
- Evidence: upstream repositories (androidx/androidx license metadata: Apache-2.0); Maven POM for `androidx.compose.material3` declares "The Apache Software License, Version 2.0"
- Usage: Android application and instrumentation tests.
- Redistribution: resolved as Gradle dependencies; not vendored.

### JUnit 4

- Upstream: https://github.com/junit-team/junit4
- Version: 4.13.2
- License: EPL-1.0
- Evidence: Maven POM `<licenses>`; upstream repository license metadata
- Usage: JVM unit tests.
- Redistribution: resolved as a Gradle dependency.

### Gradle and Android Gradle Plugin

- Upstreams: https://github.com/gradle/gradle, Android Gradle Plugin (Google Maven, AOSP `platform/tools/base`)
- Versions: Gradle 8.13 (`gradle-wrapper.properties`), AGP 8.13.2 (`android/build.gradle.kts`)
- License: Gradle is Apache-2.0 (upstream LICENSE; `gradle-wrapper.jar` is the standard wrapper binary redistributed with the project). The AGP Maven POM and jar contain no license metadata: **NEEDS_REVIEW** (build-only tool; not redistributed by this repository).

## Models

### URLBERT base encoder

- Upstream: https://huggingface.co/CrabInHoney/urlbert-tiny-v6
- Revision: `020744435b3be870dabb2bba0b41237bea69b84b`
- License: Apache-2.0
- Evidence: Hugging Face model metadata (`cardData.license = apache-2.0`), verified 2026-09-20. The upstream repository contains no separate LICENSE or NOTICE file; the license is declared in the model card.
- Usage: base encoder for binary BENIGN / PHISHING URL classification.
- Redistribution: this repository includes a fine-tuned ONNX export of the model (see below). PyTorch checkpoints are not redistributed.

### URLBERT binary export (ONNX)

- File: `deployment/android/v1/urlbert_binary.onnx` and `deployment/android/v2/urlbert_binary.onnx`
- SHA-256: `f81a14452e3e1e90940d734796b86259dd54b52f85c08dc5e64dac05eb8b2ebb`
- License: Apache-2.0, as a derivative of the Apache-2.0 base encoder. A 2-class classification head was trained and the model was exported to ONNX with maximum sequence length 32.
- Redistribution: included in this repository as an Android runtime asset.
- Related file: `tokenizer.json` (same directories) is the exported tokenizer derived from the base model (Apache-2.0).

### LightGBM binary model

- File: `models/lightgbm_binary/v1/model.txt`
- License: the model was trained by this project; it is distributed under the project license (Apache-2.0). Dataset licensing does not transfer to the trained weights; dataset terms still govern the underlying data.
- Redistribution: included.

### UGDM

- File: `models/ugdm/v1/model.pt` (not redistributed; only `metadata.json` is included)
- Note: research-negative result; not part of the shipped decision path.

## Datasets

### Phishing.Database

- Upstream: https://github.com/Phishing-Database/Phishing.Database
- License: MIT
- Evidence: GitHub repository license metadata, verified 2026-09-20
- Usage: PHISHING source rows (9,894 sampled) in `dataset-v1.3.0` and source-holdout evaluation.
- Redistribution: raw phishing URLs are not included in this repository. Only aggregate counts and SHA-256 hashes appear in dataset metadata.

### Tranco

- Upstream: https://tranco-list.eu/
- License: **NEEDS_REVIEW**. The upstream page describes licenses of the provider lists it aggregates (Majestic CC BY 3.0, Chrome UX Report CC BY-SA 4.0, Cloudflare Radar CC BY-NC 4.0) but does not state a license for the Tranco list itself.
- Usage: BENIGN seed domains in `dataset-v1.3.0`.
- Redistribution: not redistributed. Only counts and hashes appear in metadata.

### OpenPhish Community Feed

- Upstream: https://openphish.com/phishing_feeds.html
- License: **NEEDS_REVIEW**. The official page references Terms of Use and distinguishes commercial use; no open license text was found.
- Usage: PHISHING source rows (106 sampled).
- Redistribution: not redistributed.

### CERT Polska Warning List

- Upstream: https://cert.pl/en/warning-list/
- License: **NEEDS_REVIEW**. No license statement was found on the official English page during this review.
- Usage: PHISHING source rows (10,000 sampled).
- Redistribution: not redistributed.

### URLhaus

- Upstream: https://urlhaus.abuse.ch/
- License: **NEEDS_REVIEW**. The official API documentation states the API is available "free of charge under the fair use principles" and requires agreement to the abuse.ch Terms of Use; it is not an open data license.
- Usage: MALWARE / threat-intelligence provider. 7,833 indicator digests are included in the TI assets.
- Redistribution: raw indicators are not redistributed. The repository contains SHA-256 digests of indicators only.

### ThreatFox

- Upstream: https://threatfox.abuse.ch/
- License: **NEEDS_REVIEW**, same abuse.ch fair-use terms as URLhaus.
- Usage: MALWARE / threat-intelligence provider; 2,642 indicators in the frozen snapshot.
- Redistribution: raw indicators are not redistributed; SHA-256 digests only.

### Common Crawl

- Upstream: https://commoncrawl.org/
- License: **NEEDS_REVIEW**. Official terms were not verified during this review.
- Usage: 7 BENIGN candidate URLs for the optional `FULL_URL` view; not used in the shipped model.
- Redistribution: not redistributed.

## Data Resources

### Public Suffix List

- Upstream: https://publicsuffix.org/ ; repository https://github.com/publicsuffix/list
- License: MPL-2.0
- Evidence: upstream repository LICENSE (MPL-2.0), verified 2026-09-20
- Redistributed files:
  - `deployment/android/v1/public_suffixes.txt`
  - `deployment/android/v2/public_suffixes.txt`
- How the files are produced: `src/deployment/export_android.py` reads the Public Suffix List snapshot bundled with `tldextract` (offline, `suffix_list_urls=()`), encodes IDN labels to punycode and sorts the result. The rules themselves are not added or removed.
- License obligations: the files remain under MPL-2.0; this repository does not relicense them. A copy of the license text is provided at `licenses/MPL-2.0.txt`.

## Generated project assets

These are produced by this project and are not third-party content:

- `deployment/android/v1/golden_set.json` and the v2 copy: synthetic, redacted fixtures.
- `deployment/android/v2/policy_v2_golden.json`: expectations generated from the frozen fixtures.
- `deployment/security/adversarial_urls_v1.json`: synthetic corpus generated by `scripts/build_adversarial_corpus.py`.
- `deployment/android/v*/threat_intel_sha256.txt`, `ti_bundle.json` and `data/processed/ugdm-v1.0.0/threat_intel_snapshot.json`: SHA-256 indicator digests derived from the URLhaus / ThreatFox snapshots listed above.
- `data/processed/**/*.json`: dataset metadata records (counts, hashes, split statistics).

## Not redistributed in this repository

- Raw and processed datasets (phishing / malware URLs).
- URLBERT PyTorch checkpoints (`best.pt`, `last.pt`).
- UGDM model weights.
- Production-signed APK / AAB and the production keystore or any signing material.
