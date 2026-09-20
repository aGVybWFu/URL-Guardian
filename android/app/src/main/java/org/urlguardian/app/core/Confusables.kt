package org.urlguardian.app.core

import java.net.IDN
import java.text.Normalizer
import java.util.Locale

object Confusables {
    private val map: Map<Char, Char> = mapOf(
        'а' to 'a', 'в' to 'b', 'е' to 'e', 'ё' to 'e', 'к' to 'k', 'м' to 'm', 'н' to 'h', 'о' to 'o',
        'р' to 'p', 'с' to 'c', 'т' to 't', 'у' to 'y', 'х' to 'x', 'ѕ' to 's', 'і' to 'i', 'ј' to 'j',
        'ԁ' to 'd', 'ɡ' to 'g', 'ь' to 'b', 'г' to 'r', 'п' to 'n',
        'α' to 'a', 'β' to 'b', 'ε' to 'e', 'ι' to 'i', 'κ' to 'k', 'ο' to 'o', 'ρ' to 'p', 'τ' to 't',
        'υ' to 'u', 'ν' to 'v', 'μ' to 'u', 'χ' to 'x', 'γ' to 'y',
        'ł' to 'l', 'ø' to 'o', 'đ' to 'd', 'ı' to 'i', 'ſ' to 's',
        '0' to 'o', '1' to 'l', '3' to 'e', '4' to 'a', '5' to 's', '6' to 'b', '7' to 't', '8' to 'b', '9' to 'g',
    )
    private val digraphs = listOf("rn" to "m", "vv" to "w")
    private val splitter = Regex("[^\\p{L}\\p{N}]+")

    const val MIN_ALIAS_LENGTH = 4

    fun skeleton(value: String): String {
        val decomposed = Normalizer.normalize(value, Normalizer.Form.NFKD).lowercase(Locale.ROOT)
        val output = StringBuilder()
        for (character in decomposed) {
            map[character]?.let { output.append(it); continue }
            val type = Character.getType(character)
            if (type == Character.NON_SPACING_MARK.toInt() ||
                type == Character.COMBINING_SPACING_MARK.toInt() ||
                type == Character.ENCLOSING_MARK.toInt()
            ) continue
            if (Character.isLetterOrDigit(character)) output.append(character)
        }
        return output.toString()
    }

    fun skeletonVariants(value: String): Set<String> {
        val variants = mutableSetOf(skeleton(value))
        for ((source, target) in digraphs) {
            val additions = variants.map { it.replace(source, target) }
            variants.addAll(additions)
        }
        return variants
    }

    fun labelTokens(value: String): Set<String> {
        val tokens = mutableSetOf<String>()
        for (part in value.replace('_', ' ').split(splitter)) {
            for (variant in skeletonVariants(part)) {
                if (variant.length >= MIN_ALIAS_LENGTH) tokens.add(variant)
            }
        }
        return tokens
    }

    fun looksConfusable(value: String): Boolean = value.lowercase(Locale.ROOT).any { !it.isAscii() || it.isDigit() }

    fun idnaDecode(label: String): String {
        if (!label.startsWith("xn--")) return label
        return try { IDN.toUnicode(label) } catch (_: Exception) { label }
    }

    private fun Char.isAscii(): Boolean = code < 128
}
