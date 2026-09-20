package org.urlguardian.app.core

import org.json.JSONArray
import org.json.JSONObject

object CanonicalJson {
    fun stringify(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is Boolean -> if (value) "true" else "false"
        is Int -> value.toString()
        is Long -> value.toString()
        is String -> JSONObject.quote(value)
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { stringify(value.get(it)) }
        is JSONObject -> value.keys().asSequence().sorted()
            .joinToString(",", "{", "}") { key -> JSONObject.quote(key) + ":" + stringify(value.get(key)) }
        else -> throw IllegalArgumentException("unsupported canonical JSON type: ${value.javaClass.name}")
    }
}
