# 資料集說明

這個 repository 不包含原始或處理後的資料檔。原因有兩個：

1. 資料內容包含大量仍在活動的 phishing / malware URL，公開散布會造成風險。
2. 各來源網站有各自的服務條款與授權，本專案沒有逐一取得再散布的授權。

因此只保留 dataset metadata（`data/processed/` 下的 JSON），內含來源、數量、split 統計與 SHA-256，足以驗證實驗設定，但不含任何 URL。

## 來源

| 來源 | 用途 | 備註 |
| --- | --- | --- |
| [Tranco](https://tranco-list.eu/) | BENIGN | research ranking；匯入後表示為 `https://<domain>/` |
| [OpenPhish Community Feed](https://openphish.com/phishing_feeds.html) | PHISHING | full URL；樣本數少 |
| [CERT Polska Warning List](https://cert.pl/en/warning-list/) | PHISHING | domain-level，具波蘭地域偏差 |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | PHISHING | MIT license；社群回報 |
| [URLhaus](https://urlhaus.abuse.ch/) | MALWARE（情資） | Abuse.ch；export API 需要 Auth-Key |
| [ThreatFox](https://threatfox.abuse.ch/) | MALWARE（情資） | Abuse.ch；header 驗證 |
| [Common Crawl](https://commoncrawl.org/) | BENIGN `FULL_URL` | 只查 Index metadata；候選樣本極少 |

`configs/` 與 `scripts/download_data.py` 保留官方端點 allowlist 與 snapshot 流程。URLhaus 的 export API 要求 Auth-Key 放在 HTTPS path，程式以窄範圍例外處理，且所有錯誤訊息與 log 都會遮蔽該值；其他來源不得使用這種形式。

## 任務與標籤

- 目前 ML 任務：binary phishing，`BENIGN=0`、`PHISHING=1`（`dataset-v1.3.0`）。
- MALWARE 不在 ML label space 內，由 Threat Intelligence layer 以證據處理。
- 模型輸入是 `DOMAIN_ONLY`：registrable domain 文字表示，最大長度 32。

## `dataset-v1.3.0` 統計

| 項目 | 值 |
| --- | --- |
| Rows | 40,000（BENIGN 20,000 / PHISHING 20,000） |
| Unique registrable domains | 40,000+（依 metadata 記錄） |
| PHISHING 來源分佈 | CERT Polska 10,000、Phishing.Database 9,894、OpenPhish 106 |
| BENIGN 來源 | Tranco 19,999、Common Crawl 1 |
| 單一 phishing 來源上限 | 50% |
| Synthetic / duplicate rows | 0 |
| Split | registrable domain group split，70 / 15 / 15，seed 42 |
| Split 大小 | Train 28,000 / Validation 6,000 / Test 6,000 |
| Frozen Test Set SHA-256 | `379c753e8744e9906c68b0bac69ab69525abc27c1bf6de2ff8eecdef5a97fdea` |
| Test Manifest SHA-256 | `bf640e52884a4b86d5edd6af25f686df3bc6534a181756161caf9c2721f84460` |

完整 metadata 位於 `data/processed/v1.3.0/dataset_metadata.json`；公開版本只把其中的絕對本機路徑改成 repository 相對路徑，其餘欄位不變。`dataset-v1.0.0` 與 `dataset-v1.2.0` 的 metadata 另外保留作為歷史記錄。

`data/processed/ugdm-v1.0.0/threat_intel_snapshot.json` 是 UGDM 使用的凍結 Threat Intelligence snapshot。內容只有 7,833 個 indicator 的 SHA-256 digest、provider 統計與時間戳，沒有 URL 或個資，因此一併保留。

## 前處理

1. 來源 snapshot 保存為 `data/raw/snapshots/`，記錄下載時間、SHA-256 與筆數。
2. Cleaner 移除空值、錯誤 label、非 HTTP(S)、無法解析、完全重複與正規化後重複的資料；同一 normalized URL 出現不同 label 時整列排除並寫入 conflict report。
3. Normalizer 處理 scheme、host 大小寫、trailing dot、port、IPv4 / IPv6、IDN / Punycode、percent encoding、path、query 與 fragment，不任意改寫 path / query。
4. `tldextract` 搭配套件內建的 Public Suffix List snapshot 計算 registrable domain，執行時不連網。
5. Splitter 以 registrable domain 分組，輸出前 assert 三組交集為零。
6. Test Manifest 在第一次建立時封存 Test CSV 的 SHA-256、筆數與 domain 數；內容改變時 pipeline 直接停止。

## 重建方式

重建需要自行向各官方來源取得資料，並遵守其條款：

```powershell
.\.venv\Scripts\python.exe scripts\download_data.py --source tranco --download
.\.venv\Scripts\python.exe scripts\download_data.py --source openphish --download
.\.venv\Scripts\python.exe scripts\download_data.py --source cert_polska --download
.\.venv\Scripts\python.exe scripts\download_data.py --source phishing_database --download
.\.venv\Scripts\python.exe scripts\build_dataset_v13.py
```

URLhaus 與 ThreatFox 需要各自的 Auth-Key，只透過環境變數或未提交的 `.env` 提供：

```powershell
$env:URLHAUS_AUTH_KEY = "your key"
$env:THREATFOX_AUTH_KEY = "your key"
```

`data/processed/*/dataset_metadata.json` 可用來比對重建結果的來源分佈與 manifest 雜湊；由於社群來源每天變動，逐位元重建不會完全一致。

## 使用限制

- 資料中的 URL 一律只當作字串處理，不會被開啟、解析或連線。
- 社群 feed 可能有 false positive；Tranco 的熱門 domain 也不等於已人工確認的良性網站。
- 同一個 registrable domain 不會跨 Train / Validation / Test；這是本專案最低限度的 leakage 防線。
