# Changelog

## [Unreleased]

### 新增

- 公開版本新增 `LICENSE`（Apache License 2.0）、`THIRD_PARTY_NOTICES.md`、
  `SECURITY.md`、`CITATION.cff` 與 `licenses/MPL-2.0.txt`。
- 新增 `docs/dependency_inventory.md`：第三方相依與資料來源盤點。

### 變更

- `CHANGELOG.md` 與 `SECURITY.md` 改為繁體中文；`THIRD_PARTY_NOTICES.md` 與
  `docs/dependency_inventory.md` 保留英文，方便對照上游授權文字。
- `docs/development.md` 補充 androidTest instrumented 測試需要本地 probe
  assets 的說明。

### 修正

- `docs/evaluation.md` 不再指向公開版本未包含的 `reports/`。

### 安全性

- 移除兩份 `urlbert_binary.onnx` 內嵌的 `pkg.torch.onnx.stack_trace` node
  metadata（原含本機絕對路徑）。65 筆 fixtures 的推論輸出不變（max logit
  diff 0.0），所有記錄的雜湊同步更新。
- 啟用 GitHub private vulnerability reporting。

## [1.0.0] - 2026-09-20

### 新增

- 以使用者自行保管的 key 完成 release APK 與 AAB 的 production signing；兩個
  artifact 都與 keystore 憑證完成驗證。
- `deployment/android/v4` production deployment manifest，以及移除本機路徑與
  憑證指紋的公開版本。
- 在合格的 ARM64 實機完成最終驗證：安裝稽核、smoke test、UI E2E、benchmark
  sanity 與 500 次穩定性測試。
- Production artifact 稽核：signed APK 與 AAB 的 ABI、permission、secret
  pattern 與網路函式庫掃描。

### 變更

- 版本升為 1.0.0（`versionCode 11`、`versionName 1.0.0`）。
- 重新產生 `deployment/android/v2/`，只更新版本標記；所有凍結資產維持位元相同
  並通過 hash 驗證。
- Release gate 改用 production artifact 的 `NoInternet`、`SecretScan` 與 runtime
  R8 證據，不再使用 release candidate。

### 修正

- Android 重建 `MainActivity` 時保留並還原手動分析結果。

### 安全性

- Signed release package 未宣告 `INTERNET`、`ACCESS_NETWORK_STATE` 或任何
  dangerous permission。
- 兩個 production artifact 的 secret、keystore 與網路函式庫掃描皆為乾淨；
  signing material 不在 repository 內。

## [0.10.0] - 2026-09-20

### 新增

- Adversarial URL corpus v1：46 個 URL 案例、12 個品牌案例與 8 個短網址案例，
  由腳本產生並鎖定，Python 與 Kotlin 兩邊重播，作為跨語言 parser parity 契約。
- 對 `javascript:`、`file:`、`content:`、`intent:`、`data:`、`ftp:`、`ws:`
  明確回傳 `UNSUPPORTED_SCHEME`。
- Temporal TI snapshot history：idempotent 註冊、Android 端回復上一版、
  資訊性 staleness（FRESH / STALE / OUTDATED）。
- 資產失敗時 fail closed：模型或 tokenizer 損毀、缺少時顯示 `UNAVAILABLE`，
  不讓 App crash。
- 實機 ARM64 驗證 harness 與報告；release-candidate artifact 稽核、
  dependency report 與 production-readiness 稽核。

### 變更

- 版本 0.10.0（`versionCode 10`）。
- Release build 開啟 R8 minify 與 resource shrinking，keep 規則限定範圍。
- ABI splits 改為 opt-in；預設 build 產生 universal APK 與 AAB。
- 顯示層 redaction 也隱藏 userinfo 憑證。

### 修正

- Kotlin parser parity：超過 65535 的 port 與 Python 一樣拒絕。
- scheme-relative 與 `javascript:`／`data:` 輸入回傳穩定的 scheme 拒絕，不再
  是一般的 parse error。

## [0.9.0] - 2026-09-20

### 新增

- `BrandCatalogV1`（54 個品牌）：IDN／punycode 解碼、confusable skeleton 比對、
  token 邊界比對、官方網域保護與文件化的品牌風險分數；附 Kotlin 對應實作。
- `ShortenerCatalogV1`（26 個網域）；短網址只產生 REVIEW，不會單獨 BLOCK。
- Redirect 契約：`RedirectResolver` 與離線 `NoOpRedirectResolver`。
- `DecisionPolicyV2`（品牌、官方網域、短網址與 redirect 規則）；
  `DecisionPolicyV1` 仍是預設引擎。
- TI Bundle v1：7,833 個 indicator digest、兩個 catalog 與 canonical integrity
  digest；atomic import，損毀 bundle 可 rollback。
- Explainability UI：reason code、品牌／短網址／redirect 證據、引擎版本與
  bundle 來源。

### 修正

- Windows 非 ASCII 路徑下的 Android JVM 測試：build 目錄導向 ASCII 路徑。
- Android 11+ package visibility 下的外部瀏覽器 handoff。

## [0.8.0] - 2026-09-20

### 新增

- Binary URLBERT ONNX exporter、凍結的 Android deployment manifest、完整
  tokenizer JSON、public suffix snapshot、精簡 threat intelligence index 與
  65 筆 golden set。
- Kotlin／Compose Android App：手動分析、`ACTION_VIEW` 攔截、明確的外部瀏覽器
  handoff，沒有 WebView。
- Kotlin parity 測試：normalization、ByteLevel BPE token ID、URL 特徵、ONNX
  機率、`DecisionPolicyV1`、TI 狀態、malformed 輸入、manifest integrity、
  redaction 與 secret 掃描。

### 安全性

- 每個模型決策前都先執行 confirmed-malicious hard guardrail。
- 移除 ONNX Runtime 相依帶入的 `INTERNET`、`ACCESS_NETWORK_STATE` 權限與
  telemetry initializer。

## [0.7.0] - 2026-09-20

### 新增

- `UGDM` 多任務決策模型（33,482 參數）：31 個特徵、availability mask、三個
  head，以 policy-supervised 目標訓練。
- URLBERT out-of-fold pipeline：在凍結 Train 內以 registrable domain 做 5-fold
  group split，row leakage 0、domain overlap 0。
- `DecisionPolicyV1` 與 `DecisionCostV1`，threshold 只由 Validation 擬合。
- 評估包含 baselines、ablations、operational 指標、calibration、
  permutation importance 與 guardrail probe。

### 備註

- **UGDM 未展現足夠效益。** Test expected cost 0.8682 略差於 deterministic
  `DecisionPolicyV1` 0.8599，較適合描述為 policy distillation。此負面結果是
  Phase 3 的主要發現。

## [0.6.0] - 2026-09-20

### 新增

- `dataset-v1.3.0`：binary BENIGN／PHISHING dataset，phishing 來源有上限，
  新的 frozen Test Manifest。
- Phishing.Database provider，含 publisher SHA-256 驗證。
- `src/threat_intel`：`UrlHausProvider` 與 `ThreatFoxProvider`，只讀本機
  snapshot。
- Binary metrics 與 Phase 2.6 評估，包含 source-holdout 實驗。

### 變更

- 主要 ML 任務改為 binary phishing；MALWARE 移到 Threat Intelligence layer。
  `UNKNOWN` 不當成 `SAFE`。

### 備註

- Temperature scaling 讓兩個 binary 模型的 ECE 略升（原本已接近校準）；正式
  版本保留 uncalibrated 輸出，兩種狀態都記錄。

## [0.5.0] - 2026-09-20

### 新增

- `dataset-v1.2.0`：`natural` 與 `artifact_controlled` 兩種 sampling regime、
  host type 追蹤與新的 frozen Test Manifest。
- ThreatFox provider，使用官方 abuse.ch API 與 header 驗證。
- `LightGBM_DOMAIN_ONLY_V2` 與 `_NOIP` 特徵 ablation。
- Temperature scaling、NLL、Brier、ECE 與 reliability 分析；threshold 與
  calibration 只由 Validation 擬合。
- External-source holdout：訓練完全移除 ThreatFox，評估其 frozen Test rows。

### 備註

- Phase 2.5 降低了 IP host artifact，但沒有得到可泛化的 MALWARE detector：
  Non-IP MALWARE recall 0.0325、ThreatFox source-holdout recall 0.0027。

## [0.4.0] - 2026-09-20

### 新增

- Phase 2 `src.models.urlbert` 套件、`configs/urlbert.yaml` 與 `urlbert`
  optional dependency group。
- 第一個正式 `URLBERT_DOMAIN_ONLY_V1` checkpoint 與 `dataset-v1.1.0` 的 Test
  metrics。
- Error analysis、IP subgroup 分析、source bias 分析與 desktop research
  benchmark。

## [0.3.0] - 2026-09-20

### 新增

- OpenPhish Community Feed 與 CERT Polska Warning List provider，附不可變
  snapshot metadata。
- 官方 URLhaus export API 所需的窄範圍 credential-in-path 處理；credential 在
  所有輸出都遮蔽。
- Common Crawl domain 查詢，含每 domain 上限與有限重試。
- 官方 experiment gate 與 per-view eligibility。
- `dataset-v1.1.0` 的第一個正式 `DOMAIN_ONLY` LightGBM baseline。

## [0.2.0] - 2026-09-20

### 新增

- 不可變來源 snapshot 與來源取得 metadata。
- `DOMAIN_ONLY` 與 `FULL_URL` dataset view，共用 registrable domain 分配、
  Dataset Bias Audit 與封存的 Test Manifest。
- Multiclass one-vs-rest macro AUROC／AUPRC 評估。
