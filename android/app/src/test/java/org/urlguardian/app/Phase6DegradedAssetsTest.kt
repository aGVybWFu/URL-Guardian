package org.urlguardian.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.urlguardian.app.core.ByteLevelBpeTokenizer
import org.urlguardian.app.core.ThreatIntelIndex
import org.urlguardian.app.core.ThreatIntelStatus
import org.urlguardian.app.core.TiBundle
import org.urlguardian.app.core.UrlBertOnnx

class Phase6DegradedAssetsTest {
    @Test(expected = Exception::class)
    fun corrupt_model_bytes_fail_closed() {
        UrlBertOnnx(byteArrayOf(0, 1, 2, 3, 4, 5))
    }

    @Test(expected = Exception::class)
    fun invalid_tokenizer_json_fails_closed() {
        ByteLevelBpeTokenizer.fromJson("{\"not\":\"a tokenizer\"}")
    }

    @Test fun unreadable_intelligence_index_reports_error_not_safe() {
        val index = ThreatIntelIndex.fromText("this is not a digest list")
        assertEquals(ThreatIntelStatus.ERROR, index.lookup(
            org.urlguardian.app.core.UrlNormalizer(org.urlguardian.app.core.PublicSuffixIndex.fromText("com")).normalize("https://example.com/"),
        ))
        assertEquals(0, index.indicatorCount())
    }

    @Test fun corrupted_bundle_bytes_are_rejected() {
        val verification = TiBundle.verify(byteArrayOf(1, 2, 3))
        assertFalse(verification.ok)
        assertEquals("bundle_not_json", verification.reason)
    }

    @Test fun unavailable_index_is_not_unknown() {
        assertEquals(
            ThreatIntelStatus.UNAVAILABLE,
            ThreatIntelIndex.unavailable().lookup(
                org.urlguardian.app.core.UrlNormalizer(org.urlguardian.app.core.PublicSuffixIndex.fromText("com")).normalize("https://example.com/"),
            ),
        )
    }
}
