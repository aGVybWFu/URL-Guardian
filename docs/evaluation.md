# 評估結果

所有數字取自原始開發 repository 的正式評估輸出（該批報告未包含在這個公開版本中）；Test Set 在模型與 threshold 決定後只評估一次，不會用於調參。各階段使用各自的 frozen Test Manifest，重新切分一律禁止。

## Phase 1.5：三類 LightGBM baseline

`dataset-v1.1.0`、`DOMAIN_ONLY`，LightGBM 三類（BENIGN / PHISHING / MALWARE）：

| 指標 | 值 |
| --- | ---: |
| Accuracy | 0.714920 |
| Macro F1 | 0.775166 |
| PHISHING Recall | 0.725017 |
| MALWARE Recall | 0.910221 |
| BENIGN FPR | 0.342193 |
| Malicious FNR | 0.229845 |
| AUROC（OvR macro） | 0.855949 |
| AUPRC（OvR macro） | 0.818211 |

Bias audit 顯示明顯 source artifact，這些數字只作受限 baseline。

## Phase 2：URLBERT v1

同一個 `dataset-v1.1.0` frozen Test Set：

| 指標 | LightGBM | URLBERT |
| --- | ---: | ---: |
| Accuracy | 0.714920 | 0.819864 |
| Macro F1 | 0.775166 | 0.854036 |
| PHISHING Recall | 0.725017 | 0.780609 |
| MALWARE Recall | 0.910221 | 0.910221 |
| BENIGN FPR | 0.342193 | 0.162458 |
| Malicious FNR | 0.229845 | 0.186599 |
| AUROC | 0.855949 | 0.921941 |
| AUPRC | 0.818211 | 0.896632 |

兩個模型的 MALWARE Recall 完全相同（0.910221），原因是 Test set 中 659 筆 IP-host MALWARE 全部答對、65 筆非 IP MALWARE 全部答錯。分數主要由「host 是不是 IP」決定，不是可泛化的惡意模式。

## Phase 2.5：artifact remediation

`dataset-v1.2.0` 加入 2,642 筆 ThreatFox domain-hosted malware，`artifact_controlled` regime：

| 模型 | Macro F1 | PHISHING Recall | MALWARE Recall | BENIGN FPR | AUROC |
| --- | ---: | ---: | ---: | ---: | ---: |
| LightGBM V2 | 0.649526 | 0.715898 | 0.512545 | 0.354990 | 0.785048 |
| LightGBM V2 no-IP | 0.647930 | 0.715234 | 0.507766 | 0.352981 | 0.785157 |
| URLBERT V2 | 0.719103 | 0.724527 | 0.501792 | 0.141661 | 0.868927 |

Subgroup（LightGBM V2 full / no-IP）：

| Subgroup | Malware Recall |
| --- | ---: |
| IP host（406 筆） | 1.000000 / 1.000000 |
| Non-IP host（431 筆 malware） | 0.053364 / 0.044084 |

ThreatFox source-holdout（訓練完全移除 ThreatFox，評估其 372 筆 frozen Test rows）：Malware Recall **0.002688**。

結論：移除 IP 特徵無法修正問題；`DOMAIN_ONLY` 表示法無法泛化到 domain-hosted malware。這個負面結果直接導致 Phase 2.6 把 MALWARE 移出 ML label space。

## Phase 2.6：binary phishing

`dataset-v1.3.0`（BENIGN 20,000 / PHISHING 20,000），同一個 frozen Test Set：

| 指標 | LightGBM binary | URLBERT binary |
| --- | ---: | ---: |
| Accuracy | 0.655500 | 0.747833 |
| Precision | 0.660307 | 0.765353 |
| Recall | 0.644282 | 0.716755 |
| F1 | 0.652196 | 0.740258 |
| Specificity | 0.666778 | 0.779078 |
| Benign FPR | 0.333222 | 0.220922 |
| AUROC | 0.709186 | 0.829984 |
| AUPRC | 0.724196 | 0.840858 |

Test Set SHA-256：`379c753e8744e9906c68b0bac69ab69525abc27c1bf6de2ff8eecdef5a97fdea`
Test Manifest SHA-256：`bf640e52884a4b86d5edd6af25f686df3bc6534a181756161caf9c2721f84460`

### Source holdout

被保留來源完全不進 Train / Validation，Test 未動：

| Experiment | Held-out rows | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| Hold out Phishing.Database | 1,498 | 1.0000 | 0.493324 | 0.660706 |
| Hold out OpenPhish | 16 | 1.0000 | 0.562500 | 0.720000 |

Phishing.Database holdout recall 0.4933，顯示可部分泛化到未見過的社群 feed；OpenPhish 只有 16 筆 Test rows，樣本不足，不能過度解讀。

### Calibration

Temperature scaling 只以 Validation 擬合，Test 只評估一次：

| 模型 | Test ECE（未校準） | Test ECE（校準後） | Temperature |
| --- | ---: | ---: | ---: |
| LightGBM binary | 0.014980 | 0.024112 | 1.150 |
| URLBERT binary | 0.023489 | 0.026866 | 0.900 |
| LightGBM V2（三類） | 0.057091 | 0.021408 | 0.750 |
| URLBERT V2（三類） | 0.127731 | 0.024702 | 0.600 |

Binary 模型原本已接近良好校準，temperature scaling 以 NLL 為目標反而讓 ECE 略升，因此正式版本保留 uncalibrated 輸出，並在 UI 標註。這是負面結果，如實保留。

## Phase 3：UGDM

`ugdm-dataset-v1.0.0` 引用 `dataset-v1.3.0` 的 frozen split，沒有重新切分。Risk / Action 目標為 `DecisionPolicyV1` 的 `POLICY_SUPERVISED` 輸出，不是人類 ground truth。

Test expected decision cost（越低越好）：

| Approach | Cost |
| --- | ---: |
| **DecisionPolicyV1** | **0.859941** |
| Logistic regression | 0.865524 |
| UGDM v1 | 0.868162 |
| URLBERT only | 1.330554 |

Ablations（Test expected cost）：

| Variant | Cost |
| --- | ---: |
| Full UGDM | 0.868162 |
| No Threat Intelligence | 0.877286 |
| No URLBERT probability | 1.203287 |
| Lexical only | 1.241213 |

UGDM 比它所模仿的 deterministic policy 差 0.0082，因此正式版本使用 `DecisionPolicyV1`，UGDM 保持 disabled / experimental。

Operational metrics（UGDM, Test, with guardrail）：

| 指標 | 值 |
| --- | ---: |
| Phishing block recall | 0.0000 |
| Phishing review rate | 0.8577 |
| Phishing allow rate | 0.1423 |
| Benign block rate | 0.0000 |
| Benign review rate | 0.4205 |
| Overall review rate | 0.6397 |
| Expected decision cost | 0.8682 |

Phishing block recall 為 0 的原因是 DANGEROUS 類別在訓練資料只有 6 筆，模型學不到；這個限制沒有被隱藏。

Head metrics（Test）：Risk macro F1 0.6509、Action 0.6503（`POLICY_SUPERVISED`）、Threat 0.3721（`KNOWN_MALWARE` 與 `OTHER` 無訓練樣本）。

Guardrail probe：200 / 200 confirmed indicators 全部 BLOCK（100%）。Counterfactual safety invariant violations：0。

## 校準狀態與不變量

- LightGBM / URLBERT 原始輸出：`UNCALIBRATED_PROBABILITY`。
- DecisionPolicyV1 thresholds（review 0.35 / block 0.85）只由 Validation 在 2% 部署盛行率假設下選定。
- `UNKNOWN` 情資不等於 `SAFE`；`ERROR` 與 `UNAVAILABLE` 另有狀態。
- 確認惡意一律 BLOCK，模型與 whitelist 不能覆寫。
