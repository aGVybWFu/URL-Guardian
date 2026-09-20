package org.urlguardian.app.core

import org.json.JSONObject

data class BrandEntry(
    val brandId: String,
    val displayName: String,
    val canonicalDomains: List<String>,
    val aliases: List<String>,
)

data class BrandCatalog(val catalogVersion: String, val entries: List<BrandEntry>) {
    companion object {
        val EMPTY = BrandCatalog("none", emptyList())

        fun fromJson(json: JSONObject): BrandCatalog {
            val version = json.optString("catalogVersion", "unknown")
            val array = json.optJSONArray("entries") ?: return BrandCatalog(version, emptyList())
            val entries = (0 until array.length()).mapNotNull { index ->
                val item = array.optJSONObject(index) ?: return@mapNotNull null
                BrandEntry(
                    item.optString("brandId"),
                    item.optString("displayName"),
                    item.optJSONArray("canonicalDomains").toStringList(),
                    item.optJSONArray("aliases").toStringList(),
                )
            }
            return BrandCatalog(version, entries)
        }

        private fun org.json.JSONArray?.toStringList(): List<String> {
            if (this == null) return emptyList()
            return (0 until length()).map { getString(it) }
        }
    }
}

data class ShortenerCatalog(val catalogVersion: String, val domains: List<String>) {
    companion object {
        val EMPTY = ShortenerCatalog("none", emptyList())

        fun fromJson(json: JSONObject): ShortenerCatalog {
            val version = json.optString("catalogVersion", "unknown")
            val array = json.optJSONArray("domains") ?: return ShortenerCatalog(version, emptyList())
            return ShortenerCatalog(version, (0 until array.length()).map { array.getString(it) })
        }
    }
}
