# Scripts

公開版本只保留可重現研究流程所需的工具。裝置驗證與 release tooling 依賴特定本機 toolchain、實機序號與內部報告，因此不在這個 repository 內；驗證方法與結果記錄在 `docs/android_validation.md`。

## 資料取得與建置

| 檔案 | 用途 |
| --- | --- |
| `download_data.py` | 官方來源下載 / snapshot，含 endpoint allowlist 與 credential 遮蔽 |
| `collect_commoncrawl.py` | Common Crawl Index metadata 查詢（不抓取頁面） |
| `collect_threatfox.py` | ThreatFox API 匯入（header 驗證） |
| `build_dataset.py` | v1.1.0 dataset（三類）+ bias audit |
| `build_dataset_v12.py` | v1.2.0 dataset（natural / artifact_controlled） |
| `build_dataset_v13.py` | v1.3.0 dataset（binary phishing，目前正式版本） |
| `audit_dataset.py` | Dataset Bias Audit 單獨重跑 |
| `build_adversarial_corpus.py` | 產生並鎖定 adversarial URL corpus |
| `build_ti_bundle.py` | 由凍結 snapshot 產生 TI Bundle v1 |
| `ti_snapshot_history.py` | TI snapshot history 註冊與查詢 |

## 建置稽核

| 檔案 | 用途 |
| --- | --- |
| `audit_apk.py` | APK 大小 / ABI audit |
| `audit_artifacts.py` | APK / AAB 權限、secret pattern 與網路函式庫掃描 |

## 安全限制

- 資料集中的 URL 一律只當作字串，不會被請求、解析或開啟。
- `download_data.py` 只連線到程式內明確列出的官方 host；URLhaus 的 Auth-Key 只從環境變數讀取，且所有輸出都會遮蔽。
- Snapshot metadata 會記錄 SHA-256 與筆數，供後續比對。
