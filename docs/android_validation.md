# Android 驗證

驗證分兩層：**release candidate 資格驗證（Phase 7）** 與 **production build 最終驗證（1.0.0）**。兩者是不同 artifact 的分開量測，數字不混用。

## 建置設定

| 項目 | 值 |
| --- | --- |
| `applicationId` | `org.urlguardian.app` |
| Version | 1.0.0（`versionCode 11`） |
| `minSdk` / `targetSdk` / `compileSdk` | 26 / 35 / 35 |
| Kotlin | 2.2.21 |
| Compose BOM | 2024.09.03 |
| ONNX Runtime Android | 1.30.0（CPU） |
| ABI | `arm64-v8a` + `x86_64` |
| Release hardening | R8 minify + resource shrinking |

## 跨語言 parity

以 65 筆 frozen fixtures（安全、redacted）比對 Python 與 Kotlin：

| 檢查 | 結果 |
| --- | ---: |
| Normalizer | 65 / 65 |
| Feature extractor | 65 / 65 |
| `DecisionPolicyV1` | 65 / 65 |
| PyTorch–ONNX 類別一致率 | 100% |
| 最大 logit 誤差 | `1.0133e-06` |
| 實機最大機率誤差 | `3.7128e-07` |

Adversarial corpus v1：URL 46 / 46、品牌 12 / 12、短網址 8 / 8，另含 7 種未支援 scheme，全部在解析前拒絕且無 handoff。

## Phase 7：release candidate 實機資格驗證

裝置：Xiaomi 23013PC75G（Android 15 / API 35、`arm64-v8a`、11.4 GB RAM）。受測 artifact 為 full-R8、test-signed release candidate。

### Benchmark（20 warmups + 100 measurements）

| 階段 | Average | P50 | P95 |
| --- | ---: | ---: | ---: |
| Total pipeline | 3.691156 ms | 3.402188 ms | 5.156458 ms |
| URLBERT inference | 2.963741 ms | 2.733125 ms | 4.331042 ms |
| Threat Intelligence | 0.131830 ms | 0.123906 ms | 0.179844 ms |
| Brand / shortener（合併 intel stage） | 0.187184 ms | 0.188542 ms | 0.239011 ms |

每階段時間由 production code 的 `System.nanoTime()` 記錄，不含 ADB、UI 與記憶體取樣。量測與穩定性測試在同一台裝置、螢幕開啟、USB 充電狀態下執行。

### 穩定性

500 次連續本機分析：無 crash、無 ANR、無 browser handoff；總 PSS 前後差異與取樣結果見原始報告，沒有觀察到持續成長。Thermal status 前後皆為 0。電池能量因 USB 充電中標記為 `INVALID_WHILE_USB_CHARGING`，不報告 mW 或電池續航推估。

### 實機 E2E

手動分析、ALLOW / REVIEW / BLOCK、官方品牌、品牌不符、短網址、known-malicious guardrail、TI bundle A/B 匯入、損毀 bundle 拒絕與 rollback、旋轉與 Activity recreation、瀏覽器 handoff 與 loop prevention 全部通過。7 種未支援 scheme 在畫面上顯示 `UNSUPPORTED_SCHEME`，且沒有 handoff 按鈕。

## 1.0.0 production build 最終驗證

受測 artifact 為 production-signed universal APK（`12b4a4e6…de5d33`），與 release candidate 是不同的 build。

### 安裝稽核

| 檢查 | 結果 |
| --- | --- |
| 安裝後 APK SHA-256 與 build 產物一致 | PASS |
| `versionCode 11` / `versionName 1.0.0` | PASS |
| 主 ABI `arm64-v8a` | PASS |
| `INTERNET` / `ACCESS_NETWORK_STATE` | 未宣告 |
| 其他 dangerous permission | 無 |
| VIEW + BROWSABLE + http/https 註冊於 Activity Resolver Table | PASS |

### Production benchmark sanity（20 warmups + 100 measurements）

| 階段 | Average | P50 | P95 |
| --- | ---: | ---: | ---: |
| Total pipeline | 3.942854 ms | 3.672083 ms | 5.314375 ms |
| URLBERT inference | 3.193460 ms | 2.955104 ms | 4.339843 ms |

與 Phase 7 RC baseline 的差異：P50 +0.199 ms、P95 -0.108 ms，在文件化的 1.5× sanity 上限內。這個比較只作 regression sanity，不是統計顯著性檢定。

### 功能 smoke

production-signed APK 上重跑：ui / lifecycle / bundle / benchmark probes、adapter UI E2E（ALLOW / REVIEW / BLOCK、官方品牌、品牌不符、短網址、guardrail、7 種 scheme、handoff、loop prevention、rotation）、TI 匯入與 rollback、65/65 golden parity、46/12/8 adversarial parity、500 次穩定性，全部通過。

## 方法限制

- 實機驗證涵蓋一台裝置、一個 ABI；沒有多裝置矩陣。
- Benchmark 是 warm-run latency，不是冷啟動或電池續航量測。
- R8 全縮的 release build 無法直接 instrumentation；測試以 androidTest probe APK 反射 R8 後的實際 worker，並用 APK hash 驗證受測 artifact，不是另建一個「可測試版本」。
- 效能數字只反映這台裝置的 CPU 路徑；沒有 GPU 或 NPU 結果。
- Lock/unlock 與真正離線狀態仍屬人工驗證項目；本專案沒有自動化該部分。
