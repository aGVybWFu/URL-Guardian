package org.urlguardian.app.core

object IntentLoopGuard {
    fun externalPackages(ownPackage: String, candidates: List<String>): Set<String> =
        candidates.filter { it != ownPackage }.toSet()
}
