package org.urlguardian.app.core

import java.time.LocalDate
import java.time.temporal.ChronoUnit

enum class StalenessStatus { FRESH, STALE, OUTDATED, UNKNOWN }

object BundleStaleness {
    const val FRESH_DAYS = 30L
    const val STALE_DAYS = 180L

    fun classify(createdAt: String?, today: LocalDate = LocalDate.now()): Pair<StalenessStatus, Long?> {
        if (createdAt.isNullOrBlank()) return StalenessStatus.UNKNOWN to null
        val created = try {
            LocalDate.parse(createdAt.trim().take(10))
        } catch (_: Exception) {
            return StalenessStatus.UNKNOWN to null
        }
        val age = ChronoUnit.DAYS.between(created, today)
        val status = when {
            age < 0 -> StalenessStatus.UNKNOWN
            age <= FRESH_DAYS -> StalenessStatus.FRESH
            age <= STALE_DAYS -> StalenessStatus.STALE
            else -> StalenessStatus.OUTDATED
        }
        return status to age
    }
}
