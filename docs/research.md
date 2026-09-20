# 研究設計與修正過程

## 研究問題

主要問題：輕量化本機 AI 是否能對未被既有威脅情資收錄的未知釣魚網址提供有效風險辨識？

次要問題：結合本機 AI、Threat Intelligence、URL 結構特徵、品牌冒充與 redirect 訊號後，能否改善最終風險判斷？

限制前提：所有分析只使用 URL 字串。資料集中的 URL 不會被開啟、解析、DNS 查詢或交給瀏覽器。

## 資料集演進

| Dataset | 任務 | 主要變化 |
| --- | --- | --- |
| `dataset-v1.1.0` | 三類（BENIGN / PHISHING / MALWARE） | 第一個 frozen split 與 Test Manifest |
| `dataset-v1.2.0` | 三類 + artifact 控制 | 加入 ThreatFox domain-hosted malware；natural 與 artifact_controlled 兩種 regime |
| `dataset-v1.3.0` | binary phishing | 移除 MALWARE label，改由 Threat Intelligence 處理；per-source cap 50% |

三個版本的 split 都用 registrable domain group split（seed 42），同一個 registrable domain 不會跨 Train / Validation / Test。`dataset-v1.1.0` 保留為 `LEGACY_FROZEN_BENCHMARK`，可用於比較歷史模型，但已知其 subgroup error 曾被研究者檢視，不再宣稱是未經檢視的 holdout。

## 發現一：MALWARE 分數來自 IP host artifact

Phase 2 的 subgroup 分析顯示：Test set 中 659 筆 IP-host MALWARE 全部答對，65 筆非 IP MALWARE 全部答錯；LightGBM 與 URLBERT 的 MALWARE recall 都是 0.910221（659/724）。模型學到的主要是「host 是不是 IP」。

Phase 2.5 加入 2,642 筆真實 domain-hosted malware 後重新量化：

- LightGBM V2 的 Non-IP malware recall：0.053364；移除三個 IP 特徵後：0.044084。
- ThreatFox source-holdout（訓練不含 ThreatFox）：malware recall 0.002688。

移除 IP 特徵沒有修正問題，代表模型仍依賴相關的結構訊號。這是本專案最重要的負面結果之一。

## 發現二：binary phishing 可部分泛化

Phase 2.6 把任務改為 BENIGN vs PHISHING 後，URLBERT binary 的 AUPRC 為 0.840858、F1 0.740258，明顯優於三類 MALWARE 任務的表現。Source-holdout 顯示對未見過的 Phishing.Database 仍有 recall 0.493324；OpenPhish 只有 16 筆 Test rows，樣本不足。

BENIGN FPR 0.220922 仍然偏高；這在多數安全產品情境是可接受的 trade-off（寧可 REVIEW 也不放過），但必須明確標示，不能當成低誤報率。

## 發現三：UGDM 沒有優於 deterministic policy

UGDM 以 `DecisionPolicyV1` 的輸出作為 supervised target，屬於 policy distillation。Test expected cost：UGDM 0.868162、DecisionPolicyV1 0.859941、logistic regression 0.865524、URLBERT only 1.330554。UGDM 沒有帶來改善，因此正式版本使用 `DecisionPolicyV1`，UGDM 保持 disabled。

相關限制：風險與 action 指標量測的是「與政策一致的程度」，不是安全正確性；`KNOWN_MALWARE` 與 `OTHER` 沒有訓練樣本。

## 發現四：校準實驗的結果好壞參半

- Binary 模型：temperature scaling 使 Test ECE 由 0.023489 升至 0.026866（URLBERT）、0.014980 升至 0.024112（LightGBM），校準沒有改善，保留 uncalibrated 輸出。
- 三類 V2 模型：temperature 0.6 / 0.75 讓 ECE 由 0.127731 / 0.057091 降到 0.024702 / 0.021408，校準有效，但只用於分析。

所有未校準輸出都標記 `UNCALIBRATED_PROBABILITY`；校準後數字只視為分析 artifact。

## Threat Intelligence 與 ML 的分工

- 已知惡意：由 URLhaus / ThreatFox 的凍結 snapshot 命中，直接 BLOCK，不經模型。
- 未知網址：由 URLBERT binary 提供 phishing 訊號，經 `DecisionPolicyV1` 轉成 ALLOW / REVIEW / BLOCK。
- `UNKNOWN` 只代表情資未收錄；程式不會把它當成 SAFE。
- Threat Intelligence 特徵在 `dataset-v1.3.0` 上沒有訊號（overlap audit: BENIGN 0 hits、PHISHING 0 hits），因此 Phase 3 的 ablation 是 inert 而非有效比較。

## 尚未完成的研究項目

- Temporal holdout：契約已建立，但只有一個 snapshot 日期，狀態為 `PENDING FUTURE SNAPSHOT`，沒有偽造 split。
- Live redirect resolution：架構文件已完成，但沒有部署；目前使用 `NoOpRedirectResolver`，不會展開短網址。
- 多裝置驗證：目前只有一台 ARM64 裝置。
