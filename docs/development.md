# 開發說明

## 目錄結構

```text
src/data/            loader, normalizer, cleaner, splitter, host-type, dataset v1.2 / v1.3
src/features/        feature extractor 與 schema
src/threat_intel/    ThreatIntelligenceResult 契約與 URLhaus / ThreatFox providers
src/intel/           BrandCatalogV1、ShortenerCatalogV1 與 detection engines
src/policy/          DecisionPolicyV1 / V2 與 ReasonCode
src/ugdm/            UGDM 輸入 / 輸出 schema 與 OOF 特徵
src/models/          LightGBM / URLBERT / UGDM 訓練與預測
src/evaluation/      metrics、calibration、phase25 / phase26 pipelines
src/deployment/      ONNX / tokenizer / TI 資產 exporter 與 bundle builder
android/app/src/     Kotlin / Compose App、JVM tests 與 androidTest probes
deployment/          凍結的部署資產與 manifest
```

## 環境

- Python 3.11（`py -3.11 -m venv .venv`）
- JDK 17 與 Android SDK 35 供 Android build 使用
- 若 repository 路徑包含非 ASCII 字元，`android/build.gradle.kts` 會把 Gradle build 目錄導向 `%USERPROFILE%\ug-build\URLGuardianAndroid`，避免 JVM test worker 的 classpath argfile 編碼問題；ASCII 路徑不受影響

## 常用指令

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q src

.\android\gradlew.bat -p android testDebugUnitTest testReleaseUnitTest
.\android\gradlew.bat -p android assembleDebug
```

需要 URLBERT 與部署相依套件時：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,urlbert,deployment]"
```

## Instrumented 測試（androidTest）

`android/app/src/androidTest/` 的測試需要 `androidTest/assets/phase7/` 內的
probe 資產（`mapping.json`、`golden.json`、`adversarial.json` 與
`bundle_*.json`）。這批資產由實機驗證流程在本地依 R8 mapping 產生，公開版本
不含產製腳本，因此 instrumented 測試在這個 repository 無法直接執行；JVM 測試
（`android/app/src/test/`）不需要這些資產，可正常執行。

## 研究不變量

1. 資料集中的 URL 只當字串，不開啟、不解析、不連線。
2. 同一個 registrable domain 不得跨 Train / Validation / Test。
3. Frozen Test Set 不重新切分、不用於調參、threshold 或 calibration。
4. Train rows 的 base-model 特徵必須來自 out-of-fold 預測。
5. Calibration 與 thresholds 只在 Validation 擬合。
6. `source`、provider identity、`host_type` 與 collection time 不進模型特徵。
7. `UNKNOWN` 情資不得當成 `SAFE`。
8. Risk / Action 標籤是 `POLICY_SUPERVISED`，不是人類 ground truth。

## Secrets 與 signing

- 憑證只從環境變數或未提交的 `.env` 讀取；不得寫進 CLI、config 或測試指令。
- Production signing 只讀四個環境變數：`URL_GUARDIAN_KEYSTORE_PATH`、`URL_GUARDIAN_KEY_ALIAS`、`URL_GUARDIAN_KEYSTORE_PASSWORD`、`URL_GUARDIAN_KEY_PASSWORD`（另有選用的 `URL_GUARDIAN_KEYSTORE_TYPE`）。
- Keystore 必須位於 repository 之外；若偵測到 keystore 位於 repo 內，build 直接失敗。
- 任何工具都不得輸出、記錄或保存 secret 值；報告只允許公開憑證資訊。

## 變更流程

- 小步驟、可審查的 commit。
- 改動資料、模型、特徵或 metadata schema 時必須同步記錄 migration。
- 不以 fixture 結果取代正式研究數據。
- 版本化資產（`deployment/android/vN`）一經凍結不得原地修改；新版本建立新目錄。
  隱私或安全修正例外，但必須同步更新所有記錄的雜湊並重新驗證輸出。
- 移除功能前先確認不是唯一可用的研究或部署路徑。
