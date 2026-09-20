package org.urlguardian.app.core

enum class ReasonCode(val code: String, val message: String) {
    KNOWN_MALICIOUS_GUARDRAIL("KNOWN_MALICIOUS_GUARDRAIL", "威脅情資確認此網址為惡意，硬性阻擋。"),
    WHITELIST_ALLOW("WHITELIST_ALLOW", "本機白名單允許。"),
    OFFICIAL_BRAND_DOMAIN_ALLOW("OFFICIAL_BRAND_DOMAIN_ALLOW", "這是品牌官方網域，且機率低。"),
    LOW_RISK("LOW_RISK", "沒有發現明顯風險訊號。"),
    BRAND_IMPERSONATION_BLOCK("BRAND_IMPERSONATION_BLOCK", "品牌名稱出現在非官方網域，且釣魚機率高。"),
    BRAND_IMPERSONATION_REVIEW("BRAND_IMPERSONATION_REVIEW", "品牌名稱出現在非官方網域。"),
    HIGH_PROBABILITY_WITH_EVIDENCE("HIGH_PROBABILITY_WITH_EVIDENCE", "釣魚機率高，且存在其他風險訊號。"),
    SHORTENER_REVIEW("SHORTENER_REVIEW", "這是短網址，無法靜態得知最終目的地。"),
    CROSS_DOMAIN_REDIRECT_REVIEW("CROSS_DOMAIN_REDIRECT_REVIEW", "觀察到跨網域重新導向。"),
    ELEVATED_PROBABILITY("ELEVATED_PROBABILITY", "釣魚機率偏高。"),
    UNSUPPORTED_SCHEME("UNSUPPORTED_SCHEME", "只支援 http 與 https 網址，其他類型不會被分析或開啟。");

    companion object {
        const val VERSION = "ReasonCodeV1"

        fun fromCode(code: String): ReasonCode? = entries.firstOrNull { it.code == code }
    }
}
