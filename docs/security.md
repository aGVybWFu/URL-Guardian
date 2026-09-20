# 安全設計

安全回報方式與範圍見 repository 根目錄的 `SECURITY.md`。

## 網路與權限

- Release APK 未宣告 `INTERNET`、`ACCESS_NETWORK_STATE` 或任何 dangerous permission。
- 分析流程沒有 HTTP、DNS、socket 或 WebView 載入待分析 URL 的行為。
- Redirect resolution 使用 `NoOpRedirectResolver`，不展開、不連線。
- 不使用 HTTPS MITM、不執行憑證攔截。
- 開發與評估階段同樣不開啟資料集中的 URL；所有 URL 只當作字串。

## 決策安全

- 情資確認為 malicious 時直接 BLOCK（hard guardrail），模型輸出與 whitelist 不能覆寫。
- `UNKNOWN` 只代表情資未收錄，不會被當成 `SAFE`；`ERROR` 與 `UNAVAILABLE` 是 provider 健康狀態，另外處理。
- DecisionPolicyV1 thresholds 只由 Validation 在文件化的部署盛行率假設下選定，Test Set 不參與。
- Shortener 訊號只產生 REVIEW，不會單獨 BLOCK。
- 未支援 scheme（`javascript:`、`data:`、`file:`、`content:`、`intent:`、`ftp:`、`ws:`）在解析前拒絕，不進入 handoff。

## Threat Intelligence Bundle

- Bundle 匯入前驗證 canonical integrity digest；損毀的 bundle 會被拒絕，目前版本不受影響。
- 匯入採 atomic swap（pending / active / backup），失敗可以回復上一版。
- 匯入的候選檔保留在 staging 供診斷，不會自動清空。
- Bundle 內只有 indicator digests 與 catalog，沒有原始 URL 清單。

## App 與 Release

- Release build 開啟 R8 minify 與 resource shrinking；keep rules 限定在 ONNX Runtime、`org.json` 等必要項目。
- APK / AAB 經過 ABI、permission、secret pattern 與已知網路函式庫掃描。
- Repository 不含 keystore、密碼、signing properties 或 signed APK / AAB。
- Signing 只在 release owner 自己的 shell 透過環境變數提供；keystore 必須位於 repository 之外，build 會在 keystore 位於 repo 內時直接失敗。
- 顯示層對 query 值與 userinfo 做 redaction，避免把敏感字串完整顯示在畫面上。

## Secrets 處理

- URLhaus / ThreatFox / PhishTank 的憑證只從環境變數或未提交的 `.env` 讀取。
- URLhaus 官方 export API 需要把 Auth-Key 放在 HTTPS path，這是唯一例外；程式只對精確官方 endpoint 使用該形式，且所有錯誤訊息、log、metadata 與報告都會遮蔽憑證。
- 不得把憑證放進 CLI 參數、URL（除上述例外）、committed config 或測試指令。

## 已知不足

- 模型只看 URL 字串，無法防禦頁面端的 JavaScript、redirect 或 DOM 攻擊。
- 情資快照會老化，離線優先代表即時性有限。
- Brand / shortener catalog 是人工維護清單，會有 false positive 與 false negative。
- 沒有多裝置矩陣；不同廠牌 Android 的實作差異未經測試。
- 實機驗證未涵蓋 lock/unlock 與真正離線狀態的自動化。
