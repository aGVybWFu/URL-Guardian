package org.urlguardian.app.core

import java.net.IDN
import java.net.URI
import java.text.Normalizer
import java.util.Locale

data class NormalizedUrl(
    val originalUrl: String,
    val normalizedUrl: String,
    val scheme: String,
    val hostname: String,
    val port: Int?,
    val path: String,
    val query: String,
    val fragment: String,
    val subdomain: String,
    val registrableDomain: String,
)

open class UrlNormalizationException(message: String) : IllegalArgumentException(message)

class PublicSuffixIndex(suffixes: Collection<String>) {
    private val rules = suffixes.map { it.trim().lowercase(Locale.ROOT) }.filter { it.isNotEmpty() }.toHashSet()

    fun registrableDomain(host: String): Pair<String, String> {
        if (host.contains(':') || host.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))) return "" to host
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size < 2) return "" to host
        var suffixLabels = 1
        var matchedRule = false
        for (count in 1..labels.size) {
            val candidate = labels.takeLast(count).joinToString(".")
            if (candidate in rules) { suffixLabels = count; matchedRule = true }
            val wildcard = "*." + labels.takeLast(count.coerceAtMost(labels.size)).joinToString(".")
            if (wildcard in rules && count < labels.size) { suffixLabels = count + 1; matchedRule = true }
        }
        if (!matchedRule) return labels.dropLast(1).joinToString(".") to host
        val registrableCount = (suffixLabels + 1).coerceAtMost(labels.size)
        val registrable = labels.takeLast(registrableCount).joinToString(".")
        val subdomain = labels.dropLast(registrableCount).joinToString(".")
        return subdomain to registrable
    }

    companion object {
        fun fromText(text: String) = PublicSuffixIndex(text.lineSequence().toList())
    }
}

class UrlNormalizer(private val publicSuffixes: PublicSuffixIndex) {
    fun normalize(input: String, maxLength: Int = 8192): NormalizedUrl {
        val raw = Normalizer.normalize(input, Normalizer.Form.NFC).trim()
        if (raw.isEmpty() || raw.length > maxLength) throw UrlNormalizationException("網址為空或過長")
        if (raw.any { it.code < 32 || it.code == 127 }) throw UrlNormalizationException("網址包含控制字元")
        if (SchemeGuard.classify(raw) == SchemeOutcome.UNSUPPORTED_SCHEME) {
            throw UnsupportedSchemeException("僅接受 HTTP 或 HTTPS")
        }
        val candidate = if (Regex("^[A-Za-z][A-Za-z0-9+.-]*://").containsMatchIn(raw)) raw else "https://$raw"
        val uri = try { URI(candidate) } catch (_: Exception) { throw UrlNormalizationException("無法解析網址") }
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: throw UrlNormalizationException("缺少通訊協定")
        if (scheme != "http" && scheme != "https") throw UrlNormalizationException("僅接受 HTTP 或 HTTPS")
        val authority = uri.rawAuthority ?: throw UrlNormalizationException("缺少主機名稱")
        val userInfo = authority.substringBeforeLast('@', "").let { if ('@' in authority) "$it@" else "" }
        val hostPort = authority.substringAfterLast('@')
        val rawHost = when {
            hostPort.startsWith("[") -> hostPort.substringAfter('[').substringBefore(']')
            else -> hostPort.substringBeforeLast(':').takeIf { hostPort.count { it == ':' } == 1 } ?: hostPort
        }
        val hostname = try { IDN.toASCII(rawHost.trimEnd('.')).lowercase(Locale.ROOT) }
        catch (_: Exception) { throw UrlNormalizationException("主機名稱無效") }
        if (hostname.isEmpty() || hostname.any { it.isWhitespace() }) throw UrlNormalizationException("主機名稱無效")
        val port = when {
            hostPort.startsWith("[") && hostPort.substringAfter(']', "").startsWith(":") -> hostPort.substringAfter(']').removePrefix(":").toIntOrNull()
            !hostPort.startsWith("[") && hostPort.count { it == ':' } == 1 -> hostPort.substringAfterLast(':').toIntOrNull()
            else -> null
        }
        if ((hostPort.endsWith(":") || (':' in hostPort && !hostPort.startsWith("[") && port == null))) throw UrlNormalizationException("連接埠無效")
        if (port != null && port !in 0..65535) throw UrlNormalizationException("連接埠無效")
        val defaultPort = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
        val displayHost = if (hostname.contains(':')) "[$hostname]" else hostname
        val portText = if (port == null || defaultPort) "" else ":$port"
        val path = normalizePercent(uri.rawPath ?: "")
        val query = normalizePercent(uri.rawQuery ?: "")
        val fragment = normalizePercent(uri.rawFragment ?: "")
        val normalized = buildString {
            append(scheme).append("://").append(userInfo).append(displayHost).append(portText).append(path)
            if (uri.rawQuery != null) append('?').append(query)
            if (uri.rawFragment != null) append('#').append(fragment)
        }
        val (subdomain, registrable) = publicSuffixes.registrableDomain(hostname)
        return NormalizedUrl(input, normalized, scheme, hostname, port, path, query, fragment, subdomain, registrable)
    }

    private fun normalizePercent(value: String): String {
        if (Regex("%(?![0-9A-Fa-f]{2})").containsMatchIn(value)) throw UrlNormalizationException("百分比編碼無效")
        return Regex("%[0-9A-Fa-f]{2}").replace(value) { it.value.uppercase(Locale.ROOT) }
    }
}
