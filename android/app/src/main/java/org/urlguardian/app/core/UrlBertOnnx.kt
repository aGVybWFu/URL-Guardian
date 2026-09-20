package org.urlguardian.app.core

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import java.nio.LongBuffer
import kotlin.math.exp

class UrlBertOnnx(modelBytes: ByteArray) : AutoCloseable {
    private val environment = OrtEnvironment.getEnvironment()
    private val options = OrtSession.SessionOptions().apply {
        setIntraOpNumThreads(1)
        setInterOpNumThreads(1)
        setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT)
    }
    private val session = environment.createSession(modelBytes, options)

    fun predict(encoding: Encoding): FloatArray {
        OnnxTensor.createTensor(environment, LongBuffer.wrap(encoding.inputIds), longArrayOf(1, encoding.inputIds.size.toLong())).use { ids ->
            OnnxTensor.createTensor(environment, LongBuffer.wrap(encoding.attentionMask), longArrayOf(1, encoding.attentionMask.size.toLong())).use { mask ->
                session.run(mapOf("input_ids" to ids, "attention_mask" to mask)).use { result ->
                    @Suppress("UNCHECKED_CAST")
                    val logits = (result[0].value as Array<FloatArray>)[0]
                    val maximum = logits.max()
                    val exponentials = logits.map { exp((it - maximum).toDouble()) }
                    val sum = exponentials.sum()
                    return FloatArray(logits.size) { (exponentials[it] / sum).toFloat() }
                }
            }
        }
    }

    override fun close() {
        session.close()
        options.close()
    }
}
