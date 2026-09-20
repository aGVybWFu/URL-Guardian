# Deployment 資產

這個目錄保存 Android App 執行所需的凍結資產與版本記錄。Production signed APK / AAB、keystore 與簽章私鑰不在 repository 內。

## 目錄

```text
android/v1/   Phase 4 凍結的部署資產（ONNX、tokenizer、public suffixes、TI index、golden set、manifest）
android/v2/   Phase 5 起的 runtime 資產；Android build 直接使用這一版
android/v4/   1.0.0 production deployment manifest（公開版已移除本機路徑與憑證指紋）
security/     adversarial URL corpus（46 URL / 12 brand / 8 shortener，全部為合成案例）
ti/           Threat Intelligence snapshot history
```

`android/v2/` 的內容與 `android/v1/` 的凍結資產逐位元相同（hash 驗證），另外加入 TI bundle、`policy_v2_golden.json` 與更新版 feature schema。

## 主要資產

| 檔案 | 說明 |
| --- | --- |
| `urlbert_binary.onnx` | 二元分類 URLBERT export，8,474,018 bytes，SHA-256 `f81a1445…8b2ebb` |
| `tokenizer.json` | ByteLevel BPE tokenizer，SHA-256 `bd2cfa05…8c61ba9` |
| `public_suffixes.txt` | tldextract 內建 Public Suffix List snapshot（MPL-2.0） |
| `threat_intel_sha256.txt` | 7,833 個 indicator digest（只有雜湊，沒有原始 URL） |
| `ti_bundle.json` | TI Bundle v1：indicator digests + 品牌 / 短網址 catalog + integrity digest |
| `golden_set.json` | 65 筆 frozen parity fixtures（安全合成案例） |
| `policy_v2_golden.json` | DecisionPolicyV2 的離線 golden 期望值（實驗引擎） |
| `adversarial_urls_v1.json` | 跨語言 parser parity corpus |

## 版本記錄

- `android-v1`：Phase 4，執行 ONNX Runtime CPU 的離線原型。
- `android-v2`：Phase 5 起的 shipped runtime assets，預設 `DecisionPolicyV1`，`DecisionPolicyV2` 為 experimental。
- `android-v3`：Phase 6/7 release-candidate 記錄（未包含於公開版本）。
- `android-v4`：1.0.0 production release manifest（公開版見 `android/v4/deployment_manifest.json`）。

## 公開版本省略的內容

- Production signed APK / AAB
- Keystore、密碼、signing properties
- 簽章憑證的 subject 與 fingerprint
- 任何包含本機絕對路徑的 release 記錄

`android/v4/deployment_manifest.json` 保留版本、資產雜湊、ABI、SDK 與驗證結果，作為可重現性記錄。
