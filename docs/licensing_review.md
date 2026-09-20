# 授權檢視

本文記錄公開 repository（URL Guardian 1.0.0）中每個第三方元件的授權狀態、義務與處理方式。所有結論都附上證據來源；無法從官方來源確認者標記 `NEEDS_REVIEW`。

## 總表

| Component | Type | Upstream | License | Redistributed? | Obligations | Public repo handling | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| URLBERT base encoder | Model | `CrabInHoney/urlbert-tiny-v6` @ `0207444` | Apache-2.0（HF model metadata `cardData.license`） | 衍生 ONNX 有散布 | 保留授權聲明、標註修改 | `THIRD_PARTY_NOTICES.md`；ONNX 為微調後 export | PASS |
| URLBERT binary ONNX | Model（衍生） | 同上 | Apache-2.0 | 是（`deployment/android/v1`、`v2`） | 同上 + 修改說明 | 修改說明記錄於 notices | PASS |
| `tokenizer.json` | Embedded asset（衍生） | 同上 | Apache-2.0 | 是 | 同上 | 同上 | PASS |
| Public Suffix List | Data resource | `publicsuffix/list` | MPL-2.0（upstream LICENSE） | 是（`public_suffixes.txt` ×2） | 檔案維持 MPL-2.0、提供授權副本、標註產生方式 | `licenses/MPL-2.0.txt` + notices 說明 | PASS |
| Phishing.Database | Dataset | `Phishing-Database/Phishing.Database` | MIT（GitHub license metadata） | 否 | 無散布，無額外義務 | 只保留統計與雜湊 | PASS |
| Tranco | Dataset | `tranco-list.eu` | 未確認（頁面只列上游 provider 授權） | 否 | 未散布 | metadata 只有 counts / hashes | NEEDS_REVIEW |
| OpenPhish Community Feed | Dataset | `openphish.com` | 未確認（Terms of Use，區分商業使用） | 否 | 未散布 | 同上 | NEEDS_REVIEW |
| CERT Polska Warning List | Dataset | `cert.pl` | 未確認（官方英文頁無授權聲明） | 否 | 未散布 | 同上 | NEEDS_REVIEW |
| URLhaus | Dataset / TI | `urlhaus.abuse.ch` | 未確認（fair use + abuse.ch Terms of Use） | 否（只有 SHA-256 digests） | 未散布原始 indicator | digest 清單 + notices 註明 | NEEDS_REVIEW |
| ThreatFox | Dataset / TI | `threatfox.abuse.ch` | 未確認（同 abuse.ch 條款） | 否（只有 digest） | 同上 | 同上 | NEEDS_REVIEW |
| Common Crawl | Dataset | `commoncrawl.org` | 未確認 | 否 | 未散布 | metadata 只有計數 | NEEDS_REVIEW |
| ONNX Runtime | Software | `microsoft/onnxruntime` | MIT（Maven POM） | 否 | 無 | notices | PASS |
| ONNX / onnxscript | Software | `onnx/onnx`、`microsoft/onnxscript` | Apache-2.0 / MIT（upstream LICENSE、package metadata） | 否 | 無 | notices | PASS |
| PyTorch | Software | `pytorch/pytorch` | BSD-3-Clause（core；wheel 另有 bundled component 授權） | 否（training-only） | 無 | notices | PASS |
| Transformers | Software | `huggingface/transformers` | Apache-2.0 | 否 | 無 | notices | PASS |
| safetensors | Software | `huggingface/safetensors` | Apache-2.0 | 否 | 無 | notices | PASS |
| LightGBM | Software | `microsoft/LightGBM` | MIT | 否 | 無 | notices | PASS |
| pandas / NumPy / scikit-learn / joblib | Software | 各 upstream | BSD-3-Clause（NumPy metadata 另含 0BSD/MIT/Zlib/CC0-1.0 components） | 否 | 無 | notices | PASS |
| tldextract | Software | `john-kurkowski/tldextract` | BSD-3-Clause | 否 | 無 | notices | PASS |
| Matplotlib | Software | `matplotlib/matplotlib` | Matplotlib license（PSF-based） | 否 | 無 | notices | PASS |
| PyYAML | Software | `yaml/pyyaml` | MIT | 否 | 無 | notices | PASS |
| certifi | Software | `certifi/python-certifi` | MPL-2.0 | 否 | 未散布 | notices | PASS |
| pytest | Software（dev） | `pytest-dev/pytest` | MIT | 否 | 無 | notices | PASS |
| org.json | Software | `stleary/JSON-java` | Public Domain（Maven POM、upstream LICENSE） | 否 | 無 | notices | PASS |
| Kotlin / Compose / AndroidX | Software | `JetBrains/kotlin`、`androidx/androidx` | Apache-2.0（Maven POM、upstream metadata） | 否 | 無 | notices | PASS |
| JUnit 4 | Software（test） | `junit-team/junit4` | EPL-1.0（Maven POM） | 否 | 無 | notices | PASS |
| Gradle（含 wrapper jar） | Build tool | `gradle/gradle` | Apache-2.0 | `gradle-wrapper.jar`（標準 wrapper） | 無額外義務 | notices | PASS |
| Android Gradle Plugin | Build tool | Google Maven / AOSP | 未確認（POM 與 jar 皆無授權資訊） | 否（build-only） | 無 | notices 標註 | NEEDS_REVIEW |
| LightGBM binary model | Model（自有） | 本專案訓練 | 專案 Apache-2.0 | 是（`models/lightgbm_binary/v1`） | 無第三方義務 | — | PASS |
| UGDM weights | Model（自有） | 本專案訓練 | 專案 Apache-2.0 | 否 | 無 | 只保留 metadata | PASS |
| golden / adversarial / TI digest 資產 | Generated asset | 本專案產生 | 專案 Apache-2.0（digest 為第三方資料之衍生） | 是 | 註明來源 | notices「Generated project assets」 | PASS |

## URL Guardian 自有程式碼授權

### 決策

**LICENSE_DECISION = APACHE-2.0**，`LICENSE` 使用 Apache License 2.0 官方原文，未修改。

評估過的選項：

| License | 評估 |
| --- | --- |
| MIT | 最短最簡單，但沒有專利授權條款；第三方含 Apache-2.0 模型與元件時，專利條款的處理較不明確。 |
| BSD-3-Clause | 與 MIT 相近，同樣缺專利授權；需要額外撰寫 attribution 條款。 |
| Apache-2.0 | permissive、含明確專利授權、有 NOTICE/標註要求、與現有第三方結構（Apache-2.0 模型、MPL-2.0 資料檔、MIT/BSD 相依）相容。 |
| GPL-3.0 | 會對整體散布加上 copyleft，與本專案要讓模型與文件可被廣泛使用的目標不符，且非必要。 |

選擇 Apache-2.0 的實際理由：

- permissive，允許學術與商業使用，不需要開源衍生作品。
- 明確的專利授權（section 3），避免日後專利主張的不確定性。
- 有清楚的 attribution / NOTICE 機制，與本專案既有的第三方標註流程一致。
- 與目前散布內容相容：Apache-2.0 的模型衍生（ONNX）、MIT/BSD 的程式相依，以及 MPL-2.0 的 Public Suffix List 檔案（MPL-2.0 為檔案級 copyleft，與 Apache-2.0 檔案並存沒有衝突）。

### 範圍

- Apache-2.0 只涵蓋 URL Guardian 自有的原始碼與由本專案產生的資產。
- 第三方軟體、模型、資料集與資料資源維持各自的授權；詳見 `THIRD_PARTY_NOTICES.md`。
- 資料集授權由原始提供者決定，本 repository 不散布 raw malicious URL 資料集，Apache-2.0 不涵蓋任何第三方資料集。
- 模型權重另外說明：base encoder 為 Apache-2.0，散布的 ONNX 為其衍生；本專案訓練的 LightGBM 權重依專案授權散布。

### Copyright

- `LICENSE` 使用 Apache-2.0 官方文字，未填入任何姓名或個人資訊。
- 第三方 copyright 不在本專案主張範圍內，`THIRD_PARTY_NOTICES.md` 只描述來源與授權，不覆寫第三方聲明。

## MPL-2.0 處理（Public Suffix List）

- `deployment/android/v1/public_suffixes.txt` 與 `deployment/android/v2/public_suffixes.txt` 是直接散布的檔案，維持 MPL-2.0，不改成 Apache-2.0。
- 產生方式：`src/deployment/export_android.py` 讀取 tldextract 內建的 PSL snapshot（離線），將 IDN label 轉為 punycode 後排序；沒有新增或刪除規則。
- 授權副本：`licenses/MPL-2.0.txt`（Mozilla 官方文字）。
- 修改說明與來源記錄於 `THIRD_PARTY_NOTICES.md`。

## 未散布但被引用的資源

原始與處理後資料集、URLBERT PyTorch checkpoints、UGDM 權重、production-signed APK/AAB 與簽章材料都不在 repository 內。這些項目的授權狀態不影響本專案的 Apache-2.0 決策，但仍列在上表以維持完整。

## 待確認事項

- `NEEDS_REVIEW` 的資料集與建置工具（Tranco、OpenPhish、CERT Polska、URLhaus、ThreatFox、Common Crawl、AGP）。
- 這些項目目前都沒有被再散布，或只以衍生統計/雜湊形式出現；若未來要散布原始資料或 AGP 產物，需要先完成授權確認。
