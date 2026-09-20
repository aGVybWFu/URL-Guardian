# 安全性政策

## 回報弱點

URL Guardian 是研究專案，沒有專職的安全團隊，也不承諾回覆時間。

- 一般 bug：使用 GitHub Issues。
- 安全敏感問題：使用本 repository 的 GitHub private vulnerability reporting
  （Security 分頁），目前已啟用。
- 請勿在公開 issue 中包含：真實惡意網址、憑證、API key、token、個資或私有
  簽章材料。

如果回報必須提到可能是惡意的網址，請改用合成範例（例如
`https://example.com/`），並描述模式即可。

## 範圍

可接受的安全問題：

- App 進行或促成非預期的網路連線
- `UNKNOWN`／`UNAVAILABLE` 情資狀態處理錯誤，或可繞過 confirmed-malicious
  guardrail
- 解析問題導致未支援 scheme 進入瀏覽器 handoff
- TI bundle integrity 驗證可被繞過
- secrets 或 signing material 被提交進 repository

不在範圍：

- 模型品質、真實網址的 false positive／false negative
- 功能請求或決策政策變更
- 以開啟資料集網址為前提的回報；本專案不會這樣做

## 目前的安全狀態

- Android release package 未要求 `INTERNET`、`ACCESS_NETWORK_STATE` 或任何
  dangerous permission。
- 分析只使用 URL 字串：沒有 HTTP、DNS、socket、WebView 或 live crawling。
- 情資確認為 malicious 時一律 BLOCK，模型輸出不能覆寫。
- Threat Intelligence bundle 匯入前驗證 integrity，失敗會 rollback。
- Secrets 只從環境變數讀取；簽章材料不在 repository 內。
