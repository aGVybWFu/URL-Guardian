package org.urlguardian.app.core

import java.security.MessageDigest

class ThreatIntelIndex private constructor(private val digests: Set<String>?, private val loadError: Boolean = false) {
    fun lookup(normalized: NormalizedUrl): ThreatIntelStatus {
        if (loadError) return ThreatIntelStatus.ERROR
        val index = digests ?: return ThreatIntelStatus.UNAVAILABLE
        val candidates = listOf(normalized.hostname, normalized.registrableDomain).filter { it.isNotEmpty() }
        return if (candidates.any { sha256(it.trim().trim('.').lowercase()) in index }) {
            ThreatIntelStatus.KNOWN_MALICIOUS
        } else ThreatIntelStatus.UNKNOWN
    }

    fun indicatorCount(): Int = digests?.size ?: 0

    companion object {
        fun fromText(text: String): ThreatIntelIndex = try {
            val values = text.lineSequence().map { it.trim() }.filter { it.matches(Regex("[0-9a-f]{64}")) }.toSet()
            if (values.isEmpty()) ThreatIntelIndex(null, true) else ThreatIntelIndex(values)
        } catch (_: Exception) { ThreatIntelIndex(null, true) }
        fun fromDigests(values: Collection<String>): ThreatIntelIndex {
            val filtered = values.filter { it.matches(Regex("[0-9a-f]{64}")) }.toSet()
            return if (filtered.isEmpty()) ThreatIntelIndex(null, true) else ThreatIntelIndex(filtered)
        }
        fun unavailable() = ThreatIntelIndex(null)
        fun error() = ThreatIntelIndex(null, true)
        fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
