package org.urlguardian.app.core

enum class SchemeOutcome { HTTP, HTTPS, IMPLIED_HTTPS, UNSUPPORTED_SCHEME, MALFORMED }

object SchemeGuard {
    private val schemePattern = Regex("^([A-Za-z][A-Za-z0-9+.-]*):")

    fun classify(value: String): SchemeOutcome {
        val text = value.trim()
        if (text.isEmpty()) return SchemeOutcome.MALFORMED
        val match = schemePattern.find(text) ?: return SchemeOutcome.IMPLIED_HTTPS
        return when (match.groupValues[1].lowercase()) {
            "https" -> SchemeOutcome.HTTPS
            "http" -> SchemeOutcome.HTTP
            else -> SchemeOutcome.UNSUPPORTED_SCHEME
        }
    }
}

class UnsupportedSchemeException(message: String) : UrlNormalizationException(message)
