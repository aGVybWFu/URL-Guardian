# Demo

目前沒有公開的 demo 影片，也沒有散布可安裝的 production package；Production-signed binaries are not distributed in the public repository.

若要在自己的裝置上重現，只使用安全、合成的 fixture；不要開啟真實的惡意網址：

1. **ALLOW**：手動輸入 `https://example.com/`，結果為 ALLOW、`LOW_RISK`。
2. **REVIEW**：手動輸入 `https://www.paypal.com/login`，結果為 REVIEW、`ELEVATED_PROBABILITY`，並顯示「品牌官方網域」。
3. **BLOCK（品牌不符）**：手動輸入 `https://paypal-login.com/`，結果為 BLOCK、`HIGH_PROBABILITY_WITH_EVIDENCE`，沒有繼續按鈕。
4. **BLOCK（情資 guardrail）**：匯入測試用 TI bundle（加入合成 indicator digest），再分析對應的合成網址，結果為 BLOCK、`KNOWN_MALICIOUS_GUARDRAIL`。
5. **短網址**：手動輸入 `https://bit.ly/abc123`，畫面顯示短網址證據（REVIEW 提示，不會單獨 BLOCK）。
6. **未支援 scheme**：手動輸入 `file:///etc/passwd`，顯示 `UNSUPPORTED_SCHEME`，沒有 handoff。
7. **Browser handoff**：在 ALLOW / REVIEW 結果頁點「使用外部瀏覽器開啟」，確認焦點離開 URL Guardian 且不會形成迴圈。

`deployment/security/adversarial_urls_v1.json` 與 `deployment/android/v2/golden_set.json` 內的案例都是合成 fixture，可以安全重播；`.example`、`.test` 與 RFC 5737 保留 IP 不會連到真實服務。

App 沒有 `INTERNET` 權限，demo 過程不會產生任何對外請求。
