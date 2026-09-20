# 模型說明

這個 repository 保留模型 metadata，但不包含大型權重檔（URLBERT checkpoint、UGDM `model.pt`）。Android 執行所需的 ONNX 檔在 `deployment/android/v2/`，屬於部署資產。

## URLBERT binary（正式模型）

| 項目 | 值 |
| --- | --- |
| Model name | `url_guardian_urlbert_binary` |
| Model version | 0.6.0 |
| Experiment ID | `URLBERT_PHISHING_BINARY_V1` |
| Base model | `CrabInHoney/urlbert-tiny-v6`（Apache-2.0） |
| Base revision | `020744435b3be870dabb2bba0b41237bea69b84b` |
| Architecture | ModernBERT encoder + 2-class head |
| Parameters | 2,099,714（base encoder 2,033,408） |
| Input | `DOMAIN_ONLY` registrable domain，max length 32 |
| Labels | `BENIGN=0`、`PHISHING=1` |
| ONNX SHA-256 | `f81a14452e3e1e90940d734796b86259dd54b52f85c08dc5e64dac05eb8b2ebb` |
| Tokenizer SHA-256 | `bd2cfa05429338b17dd1907899ea01f8e62f67f04a86b5ccc3c199e648c61ba9` |

Metadata：`models/urlbert_binary/v1/metadata.json`。Test 指標見 `docs/evaluation.md`。

PyTorch checkpoint（`best.pt` / `last.pt`，各約 8.4 MB）未包含在公開版本；ONNX export 已包含在 `deployment/android/v2/urlbert_binary.onnx`，與上述 SHA-256 一致。

## LightGBM binary（baseline）

| 項目 | 值 |
| --- | --- |
| Experiment ID | `LIGHTGBM_PHISHING_BINARY_V1` |
| 檔案 | `models/lightgbm_binary/v1/model.txt`（約 851 KB） |
| Features | 31 個 lexical / structural features，schema 位於同目錄 `feature_schema.json` |
| Labels | `BENIGN=0`、`PHISHING=1` |

Source-holdout 版本的 metadata 位於 `models/lightgbm_binary/holdout_openphish/` 與 `holdout_phishing_database/`（只保留 metadata）。

## 其他實驗模型

- `models/lightgbm/domain_only/metadata.json`：Phase 1.5 三類 LightGBM baseline（metadata only）。
- `models/lightgbm_v2/artifact_controlled_full/metadata.json`：Phase 2.5 MALWARE artifact-controlled 版本（metadata only）。
- `models/urlbert_v2/artifact_controlled/v1/metadata.json`：Phase 2.5 URLBERT V2（metadata only）。
- `models/ugdm/v1/metadata.json`：UGDM 33,482 參數多任務模型（metadata only；`model.pt` 未公開）。

## 重建方式

重新訓練需要先依 `data/README.md` 重建 `dataset-v1.3.0`：

```powershell
.\.venv\Scripts\python.exe -m src.models.lightgbm_binary
.\.venv\Scripts\python.exe -m src.models.urlbert.train --config configs/urlbert_binary.yaml
.\.venv\Scripts\python.exe -m src.models.urlbert.evaluate --config configs/urlbert_binary.yaml
.\.venv\Scripts\python.exe -m src.models.ugdm.train --variant full
```

Base encoder 由 Hugging Face model hub 下載，revision 固定為 metadata 中記錄的 commit。常數（seed、split、thresholds、max length）都在 `configs/` 與 metadata 內；由於社群資料來源每天變動，無法逐位元重建完全相同的資料集，但可以重建同一套流程與評估協定。

## 注意事項

- 模型輸出是 uncalibrated probability，不是真實事件機率。
- 模型只看 registrable domain 字串。
- `KNOWN_MALWARE` 與 `OTHER` 在 UGDM 沒有訓練樣本，capability 未經驗證。
- Base encoder 為 Apache-2.0；本專案微調後的權重為其衍生作品，散布時保留 upstream 授權與來源標註。
