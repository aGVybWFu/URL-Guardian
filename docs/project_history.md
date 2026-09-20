# 專案歷程

## Phase 1 / 1.5 — Dataset 與 baseline

建立官方來源 snapshot、normalization、registrable domain group split 與 bias audit，並以 LightGBM 建立可比較 baseline。只在來源齊全、domain leakage 為零且 Test Manifest 已封存時，結果才標示為 `OFFICIAL_EXPERIMENT`。

## Phase 2 / 2.5 — URLBERT 與資料 artifact 分析

Phase 2 微調 URLBERT 並在同一個 frozen Test Set 上比較。Phase 2.5 為了處理 IP-host artifact，新增 `dataset-v1.2.0` 與 ThreatFox domain-hosted malware，量化後確認 `DOMAIN_ONLY` 表示法無法泛化到 malware，如實保留負面結果。

## Phase 2.6 — Binary phishing 與 Threat Intelligence

把主要 ML 任務改為 BENIGN vs PHISHING，MALWARE 交由 Threat Intelligence 以證據處理；`dataset-v1.3.0` 與對應 frozen Test Manifest 建立。

## Phase 3 — UGDM 實驗

建立 33,482 參數的多任務決策模型（31 特徵 + availability mask，三個 head），以 `DecisionPolicyV1` 的輸出作為 policy-supervised target，並用 OOF 特徵避免 stacking leakage。

結論是負面的：UGDM Test expected cost 0.8682 比 deterministic policy 的 0.8599 差，沒有採用。

## Phase 4 — ONNX 與 Android 原型

把 URLBERT binary 匯出為 ONNX，建立 Kotlin / Compose 離線原型：normalize → TI → features → ONNX → DecisionPolicyV1 → guardrail。加入 65 筆 golden fixtures 與跨語言 parity 測試，並移除相依套件帶入的 `INTERNET` / `ACCESS_NETWORK_STATE` 權限與 telemetry。

## Phase 5 — 品牌、短網址與 TI Bundle

加入 `BrandCatalogV1`（54 品牌）、`ShortenerCatalogV1`（26 網域）、redirect 契約與 TI Bundle v1（7,833 indicator digests）。`DecisionPolicyV2` 作為 experimental 引擎，預設仍是 V1。

## Phase 6 — Release hardening

R8 minify / resource shrinking、opt-in ABI splits、adversarial URL corpus v1、TI snapshot history 與 rollback、損毀資產 fail-closed、artifact audit 與 release tooling。Release candidate 在 emulator 與實機路徑完成 E2E。

## Phase 7 — 實機資格驗證

在一台 Xiaomi ARM64 裝置上驗證 full-R8 release candidate：parity、E2E、benchmark、500 次穩定性、安裝稽核與權限稽核全部通過。`QUALIFIED_FOR_1_0 = TRUE`。

## 1.0.0 — Production release

版本提升至 1.0.0（`versionCode 11`），以使用者自行保管的 production keystore 完成 APK / AAB 簽章與簽章驗證，並在同一台裝置重跑安裝稽核、ui / lifecycle / bundle / benchmark probes、UI E2E、smoke 與效能 sanity。所有 release hard gate 通過，建立本機 release commit 與 annotated tag；沒有 push、沒有發布到任何商店。

## 專案狀態摘要

| 項目 | 狀態 |
| --- | --- |
| 正式決策引擎 | `DecisionPolicyV1` |
| 正式模型 | URLBERT binary（ONNX, v0.6.0） |
| 正式 dataset | `dataset-v1.3.0`（frozen） |
| UGDM | 實驗結果為負面，disabled |
| `DecisionPolicyV2` | experimental / research only |
| Live redirect | 尚未部署 |
| Temporal holdout | 等待第二個 snapshot 日期 |
