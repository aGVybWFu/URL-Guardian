package org.urlguardian.app.core

import org.json.JSONObject
import java.security.MessageDigest

const val TI_BUNDLE_VERSION = "ti-bundle-v1"

data class TiBundleVerification(val ok: Boolean, val reason: String, val digest: String)

data class TiBundle(
    val bundleVersion: String,
    val createdAt: String,
    val policyVersion: String,
    val indicatorDigests: Set<String>,
    val brandCatalog: BrandCatalog,
    val shortenerCatalog: ShortenerCatalog,
    val canonicalDigest: String,
    val sha256: String,
) {
    companion object {
        fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes).joinToString("") { "%02x".format(it) }

        fun verify(bytes: ByteArray): TiBundleVerification {
            val root = try {
                JSONObject(String(bytes, Charsets.UTF_8))
            } catch (_: Exception) {
                return TiBundleVerification(false, "bundle_not_json", "")
            }
            if (root.optString("bundleVersion") != TI_BUNDLE_VERSION) {
                return TiBundleVerification(false, "unsupported_bundle_version", "")
            }
            val payload = root.optJSONObject("payload")
                ?: return TiBundleVerification(false, "missing_payload", "")
            val integrity = root.optJSONObject("integrity")
                ?: return TiBundleVerification(false, "missing_integrity_block", "")
            if (integrity.optString("algorithm") != "sha256") {
                return TiBundleVerification(false, "missing_integrity_block", "")
            }
            val expected = integrity.optString("canonicalDigest", "")
            val actual = try {
                sha256Hex(CanonicalJson.stringify(payload).toByteArray(Charsets.US_ASCII))
            } catch (_: Exception) {
                return TiBundleVerification(false, "payload_not_canonicalisable", "")
            }
            if (actual != expected) return TiBundleVerification(false, "integrity_digest_mismatch", actual)
            val threatIntel = payload.optJSONObject("threatIntel")
            val brands = payload.optJSONObject("brands")
            val shorteners = payload.optJSONObject("shorteners")
            if (threatIntel == null || brands == null || shorteners == null) {
                return TiBundleVerification(false, "missing_payload_sections", actual)
            }
            val digests = threatIntel.optJSONArray("indicatorDigests")
            if (digests == null || threatIntel.optInt("indicatorCount", -1) != digests.length()) {
                return TiBundleVerification(false, "indicator_count_mismatch", actual)
            }
            if (brands.optJSONArray("entries") == null || shorteners.optJSONArray("domains") == null) {
                return TiBundleVerification(false, "catalog_payload_invalid", actual)
            }
            return TiBundleVerification(true, "ok", actual)
        }

        fun parse(bytes: ByteArray): TiBundle? {
            val root = try {
                JSONObject(String(bytes, Charsets.UTF_8))
            } catch (_: Exception) {
                return null
            }
            val payload = root.optJSONObject("payload") ?: return null
            val threatIntel = payload.optJSONObject("threatIntel") ?: return null
            val digests = threatIntel.optJSONArray("indicatorDigests") ?: return null
            val digestSet = (0 until digests.length()).map { digests.getString(it) }.toSet()
            return TiBundle(
                bundleVersion = root.optString("bundleVersion"),
                createdAt = root.optString("createdAt"),
                policyVersion = root.optString("policyVersion"),
                indicatorDigests = digestSet,
                brandCatalog = BrandCatalog.fromJson(payload.optJSONObject("brands") ?: JSONObject()),
                shortenerCatalog = ShortenerCatalog.fromJson(payload.optJSONObject("shorteners") ?: JSONObject()),
                canonicalDigest = root.optJSONObject("integrity")?.optString("canonicalDigest").orEmpty(),
                sha256 = sha256Hex(bytes),
            )
        }

        fun parseVerified(bytes: ByteArray): Pair<TiBundle?, TiBundleVerification> {
            val verification = verify(bytes)
            if (!verification.ok) return null to verification
            return parse(bytes) to verification
        }
    }
}
