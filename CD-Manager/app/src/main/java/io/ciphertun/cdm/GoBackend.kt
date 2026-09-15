package io.ciphertun.cdm

import org.json.JSONObject

/**
 * Go native analysis backend.
 *
 * The actual implementation remains in backend/go/cdmengine and is packaged
 * as cdm-go.aar by gomobile. Reflection is used here because gomobile's
 * generated Java surface can differ between binding/toolchain versions.
 */
object GoBackend {
    private const val ENGINE_CLASS = "io.ciphertun.cdmgo.Engine"

    private val engine: Any? by lazy {
        runCatching {
            val clazz = Class.forName(ENGINE_CLASS)

            // gomobile normally generates a static newEngine() factory when
            // the Go package exports NewEngine().
            runCatching {
                clazz.getMethod("newEngine").invoke(null)
            }.getOrElse {
                clazz.getDeclaredConstructor().apply {
                    isAccessible = true
                }.newInstance()
            }
        }.getOrNull()
    }

    fun available(): Boolean = engine != null

    fun analyze(sample: ByteArray): GoMetrics? = runCatching {
        val instance = engine ?: return null
        val method = instance.javaClass.methods.firstOrNull {
            it.name == "analyze" &&
                it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == ByteArray::class.java
        } ?: return null

        val result = method.invoke(instance, sample) as? String ?: return null
        val json = JSONObject(result)

        GoMetrics(
            sha256 = json.optString("sha256"),
            bytes = json.optInt("bytes"),
            entropy = json.optDouble("entropy"),
            printablePercent = json.optDouble("printable"),
            binary = json.optBoolean("binary")
        )
    }.getOrNull()
}

data class GoMetrics(
    val sha256: String,
    val bytes: Int,
    val entropy: Double,
    val printablePercent: Double,
    val binary: Boolean
)
