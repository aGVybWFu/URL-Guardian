package org.urlguardian.app.core

import org.json.JSONObject
import java.text.Normalizer
import java.util.Locale

data class Encoding(val inputIds: LongArray, val attentionMask: LongArray)

class ByteLevelBpeTokenizer private constructor(
    private val vocabulary: Map<String, Int>,
    private val mergeRanks: Map<Pair<String, String>, Int>,
    private val maxLength: Int,
    private val clsId: Int,
    private val sepId: Int,
    private val padId: Int,
    private val unknownId: Int,
) {
    private val cache = HashMap<String, List<String>>()
    private val byteEncoder = buildByteEncoder()
    private val pattern = Regex("'(?:s|t|re|ve|m|ll|d)| ?\\p{L}+| ?\\p{N}+| ?[^\\s\\p{L}\\p{N}]+|\\s+(?!\\S)|\\s+")

    fun encode(input: String): Encoding {
        val normalized = Normalizer.normalize(input.lowercase(Locale.ROOT), Normalizer.Form.NFC)
        val tokens = mutableListOf<Int>()
        pattern.findAll(normalized).forEach { match ->
            val mapped = buildString {
                match.value.toByteArray(Charsets.UTF_8).forEach { byte -> append(byteEncoder[byte.toInt() and 0xff]) }
            }
            bpe(mapped).forEach { tokens += vocabulary[it] ?: unknownId }
        }
        val payload = tokens.take(maxLength - 2)
        val ids = LongArray(maxLength) { padId.toLong() }
        val mask = LongArray(maxLength)
        val withSpecial = listOf(clsId) + payload + sepId
        withSpecial.forEachIndexed { index, id -> ids[index] = id.toLong(); mask[index] = 1L }
        return Encoding(ids, mask)
    }

    private fun bpe(token: String): List<String> = cache.getOrPut(token) {
        var symbols = token.map { it.toString() }
        while (symbols.size > 1) {
            val candidate = symbols.zipWithNext().minByOrNull { mergeRanks[it] ?: Int.MAX_VALUE } ?: break
            if (mergeRanks[candidate] == null) break
            val merged = ArrayList<String>(symbols.size)
            var index = 0
            while (index < symbols.size) {
                if (index < symbols.lastIndex && symbols[index] == candidate.first && symbols[index + 1] == candidate.second) {
                    merged += candidate.first + candidate.second
                    index += 2
                } else {
                    merged += symbols[index]
                    index++
                }
            }
            symbols = merged
        }
        symbols
    }

    companion object {
        fun fromJson(text: String, maxLength: Int = 32): ByteLevelBpeTokenizer {
            val root = JSONObject(text)
            val model = root.getJSONObject("model")
            require(model.getString("type") == "BPE")
            val vocabObject = model.getJSONObject("vocab")
            val vocabulary = vocabObject.keys().asSequence().associateWith { vocabObject.getInt(it) }
            val ranks = mutableMapOf<Pair<String, String>, Int>()
            val merges = model.getJSONArray("merges")
            for (index in 0 until merges.length()) {
                val pair = merges.getJSONArray(index)
                ranks[pair.getString(0) to pair.getString(1)] = index
            }
            return ByteLevelBpeTokenizer(
                vocabulary, ranks, maxLength,
                vocabulary.getValue("[CLS]"), vocabulary.getValue("[SEP]"),
                vocabulary.getValue("[PAD]"), vocabulary.getValue("[UNK]"),
            )
        }

        private fun buildByteEncoder(): Map<Int, Char> {
            val bytes = ((33..126) + (161..172) + (174..255)).toMutableList()
            val chars = bytes.toMutableList()
            var extra = 0
            for (value in 0..255) if (value !in bytes) {
                bytes += value
                chars += 256 + extra++
            }
            return bytes.indices.associate { bytes[it] to chars[it].toChar() }
        }
    }
}
