package org.urlguardian.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.urlguardian.app.core.BundleStaleness
import org.urlguardian.app.core.BundleStatus
import org.urlguardian.app.core.BundleSource
import org.urlguardian.app.core.StalenessStatus
import java.time.LocalDate

class Phase6TiLifecycleTest {
    private val today = LocalDate.of(2026, 9, 20)

    @Test fun staleness_thresholds_are_informational() {
        val (fresh, freshAge) = BundleStaleness.classify("2026-09-20T05:09:28+00:00", today)
        assertEquals(StalenessStatus.FRESH, fresh)
        assertEquals(0L, freshAge)

        val (stale, staleAge) = BundleStaleness.classify("2026-08-01", today)
        assertEquals(StalenessStatus.STALE, stale)
        assertEquals(50L, staleAge)

        val (outdated, _) = BundleStaleness.classify("2025-01-01", today)
        assertEquals(StalenessStatus.OUTDATED, outdated)

        val (unknown, unknownAge) = BundleStaleness.classify(null, today)
        assertEquals(StalenessStatus.UNKNOWN, unknown)
        assertNull(unknownAge)

        val (future, _) = BundleStaleness.classify("2027-01-01", today)
        assertEquals(StalenessStatus.UNKNOWN, future)
    }

    @Test fun staleness_never_maps_to_invalid() {
        val statuses = listOf("2026-09-20", "2026-06-01", "2024-01-01").map { BundleStaleness.classify(it, today).first }
        assertTrue(statuses.all { it in setOf(StalenessStatus.FRESH, StalenessStatus.STALE, StalenessStatus.OUTDATED) })
    }

    @Test fun snapshot_ids_are_date_scoped() {
        assertEquals("ti-2026-09-20", BundleStatus.snapshotIdOf("2026-09-20T05:09:28+00:00"))
        assertEquals("ti-2026-09-20", BundleStatus.snapshotIdOf("2026-09-20"))
        assertNull(BundleStatus.snapshotIdOf(null))
        assertNull(BundleStatus.snapshotIdOf("bad"))
    }

    @Test fun previous_snapshot_flag() {
        assertFalse(BundleStatus.NONE.hasPrevious)
        val withPrevious = BundleStatus.NONE.copy(previousSnapshotId = "ti-2026-09-19")
        assertTrue(withPrevious.hasPrevious)
    }

    @Test fun rolled_back_source_is_distinct_from_imported() {
        val status = BundleStatus.NONE.copy(source = BundleSource.ROLLED_BACK, integrityOk = true)
        assertEquals(BundleSource.ROLLED_BACK, status.source)
        assertTrue(status.integrityOk)
    }
}
