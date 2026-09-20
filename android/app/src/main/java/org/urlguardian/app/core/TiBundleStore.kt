package org.urlguardian.app.core

import android.content.Context
import java.io.File

enum class BundleSource { ASSET, IMPORTED, ROLLED_BACK, NONE }

data class BundleStatus(
    val source: BundleSource,
    val bundleVersion: String?,
    val createdAt: String?,
    val indicatorCount: Int,
    val brandCount: Int,
    val shortenerCount: Int,
    val integrityOk: Boolean,
    val lastError: String?,
    val sha256: String?,
    val staleness: StalenessStatus = StalenessStatus.UNKNOWN,
    val ageDays: Long? = null,
    val snapshotId: String? = null,
    val previousSnapshotId: String? = null,
) {
    val hasPrevious: Boolean get() = previousSnapshotId != null

    companion object {
        val NONE = BundleStatus(BundleSource.NONE, null, null, 0, 0, 0, false, null, null)

        fun of(bundle: TiBundle, source: BundleSource, lastError: String? = null, previousSnapshotId: String? = null): BundleStatus {
            val (staleness, age) = BundleStaleness.classify(bundle.createdAt)
            return BundleStatus(
                source = source,
                bundleVersion = bundle.bundleVersion,
                createdAt = bundle.createdAt,
                indicatorCount = bundle.indicatorDigests.size,
                brandCount = bundle.brandCatalog.entries.size,
                shortenerCount = bundle.shortenerCatalog.domains.size,
                integrityOk = true,
                lastError = lastError,
                sha256 = bundle.sha256,
                staleness = staleness,
                ageDays = age,
                snapshotId = snapshotIdOf(bundle.createdAt),
                previousSnapshotId = previousSnapshotId,
            )
        }

        fun snapshotIdOf(createdAt: String?): String? {
            val date = createdAt?.trim()?.take(10)?.takeIf { it.length == 10 } ?: return null
            return "ti-$date"
        }
    }
}

data class IntelState(val bundle: TiBundle?, val status: BundleStatus) {
    companion object {
        val NONE = IntelState(null, BundleStatus.NONE)
    }
}

class TiBundleStore(private val context: Context) {
    private val activeFile = File(context.filesDir, ACTIVE_NAME)
    private val pendingFile = File(context.filesDir, PENDING_NAME)
    private val backupFile = File(context.filesDir, BACKUP_NAME)
    private val previousFile = File(context.filesDir, PREVIOUS_NAME)

    fun candidateFile(): File? = context.getExternalFilesDir(null)?.let { File(it, CANDIDATE_NAME) }

    fun candidateFiles(): List<File> = listOfNotNull(candidateFile(), File(context.filesDir, STAGING_NAME))
        .filter { it.isFile }

    fun load(): IntelState {
        var importError: String? = null
        candidateFiles().forEach { candidate ->
            val status = importCandidate(candidate)
            if (status.source != BundleSource.IMPORTED) importError = status.lastError
        }
        if (activeFile.isFile) {
            val (bundle, verification) = TiBundle.parseVerified(activeFile.readBytes())
            if (bundle != null) {
                return IntelState(
                    bundle,
                    BundleStatus.of(bundle, BundleSource.IMPORTED, importError, previousSnapshotId()),
                )
            }
            activeFile.delete()
            val asset = loadAsset()
            return asset.copy(status = asset.status.copy(source = BundleSource.ROLLED_BACK, lastError = verification.reason))
        }
        val asset = loadAsset()
        return if (importError != null) {
            asset.copy(status = asset.status.copy(source = BundleSource.ROLLED_BACK, lastError = importError))
        } else asset
    }

    fun previousSnapshotId(): String? {
        if (!previousFile.isFile) return null
        val (bundle, verification) = TiBundle.parseVerified(previousFile.readBytes())
        if (bundle == null) {
            previousFile.delete()
            return null
        }
        return BundleStatus.snapshotIdOf(bundle.createdAt)?.takeIf { verification.ok }
    }

    /** Re-activate the previously stored bundle; the caller may toggle back. */
    fun rollbackToPrevious(): BundleStatus {
        if (!previousFile.isFile) return rejected("no_previous_bundle")
        val status = importBytes(previousFile.readBytes())
        return if (status.source == BundleSource.IMPORTED) {
            status.copy(source = BundleSource.ROLLED_BACK)
        } else status
    }

    fun importCandidate(file: File): BundleStatus {
        val status = importBytes(file.readBytes())
        if (status.source == BundleSource.IMPORTED) file.delete()
        return status
    }

    fun importBytes(bytes: ByteArray): BundleStatus {
        val verification = TiBundle.verify(bytes)
        if (!verification.ok) return rejected(verification.reason)
        pendingFile.writeBytes(bytes)
        val (pendingBundle, pendingVerification) = TiBundle.parseVerified(pendingFile.readBytes())
        if (pendingBundle == null) {
            pendingFile.delete()
            return rejected(pendingVerification.reason)
        }
        val previousBytes = if (activeFile.isFile) activeFile.readBytes() else null
        if (previousBytes != null) activeFile.copyTo(backupFile, overwrite = true)
        val moved = pendingFile.renameTo(activeFile)
        if (!moved) {
            pendingFile.copyTo(activeFile, overwrite = true)
            pendingFile.delete()
        }
        val (activeBundle, activeVerification) = TiBundle.parseVerified(activeFile.readBytes())
        if (activeBundle == null) {
            if (backupFile.isFile) {
                backupFile.copyTo(activeFile, overwrite = true)
                backupFile.delete()
            } else {
                activeFile.delete()
            }
            return rejected(activeVerification.reason, rolledBack = true)
        }
        backupFile.delete()
        if (previousBytes != null) previousFile.writeBytes(previousBytes)
        return BundleStatus.of(activeBundle, BundleSource.IMPORTED, previousSnapshotId = previousSnapshotId())
    }

    private fun loadAsset(): IntelState {
        val bytes = try {
            context.assets.open(ASSET_NAME).use { it.readBytes() }
        } catch (_: Exception) {
            return IntelState.NONE
        }
        val (bundle, verification) = TiBundle.parseVerified(bytes)
        if (bundle == null) {
            return IntelState(null, BundleStatus.NONE.copy(integrityOk = false, lastError = verification.reason))
        }
        return IntelState(bundle, BundleStatus.of(bundle, BundleSource.ASSET))
    }

    private fun rejected(reason: String, rolledBack: Boolean = false) = BundleStatus(
        source = if (rolledBack) BundleSource.ROLLED_BACK else BundleSource.NONE,
        bundleVersion = null,
        createdAt = null,
        indicatorCount = 0,
        brandCount = 0,
        shortenerCount = 0,
        integrityOk = false,
        lastError = reason,
        sha256 = null,
    )

    companion object {
        const val ASSET_NAME = "ti_bundle.json"
        const val CANDIDATE_NAME = "ti_bundle.json"
        const val STAGING_NAME = "ti_bundle.import.json"
        const val ACTIVE_NAME = "ti_bundle.active.json"
        const val PENDING_NAME = "ti_bundle.pending.json"
        const val BACKUP_NAME = "ti_bundle.backup.json"
        const val PREVIOUS_NAME = "ti_bundle.previous.json"
    }
}
