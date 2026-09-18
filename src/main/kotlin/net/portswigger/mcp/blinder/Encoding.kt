package net.portswigger.mcp.blinder

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Encoding contexts a masked value can sit inside. The gateway records, per placeholder
 * occurrence, the chain of encodings that were applied to the real value at that position so
 * rehydration can reproduce the original bytes exactly (round-trip identity).
 *
 * The chain is stored innermost-first. To reconstruct the literal that appeared in the text we
 * apply [encode] left-to-right; to peel the text back to the raw value during detection we apply
 * [decode] right-to-left.
 *
 * Example: a query parameter carrying `urlEncode(base64(value))` has chain [BASE64, URL].
 * `encode`: value -> base64 -> urlEncode. `decode`: text -> urlDecode -> base64Decode.
 */
enum class Encoding(val tag: String) {
    URL("u") {
        override fun encode(s: String): String = URLEncoder.encode(s, StandardCharsets.UTF_8)
        override fun decode(s: String): String = URLDecoder.decode(s, StandardCharsets.UTF_8)
    },
    BASE64("b64") {
        override fun encode(s: String): String =
            Base64.getEncoder().encodeToString(s.toByteArray(StandardCharsets.UTF_8))

        override fun decode(s: String): String =
            String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8)
    },
    JSON("j") {
        override fun encode(s: String): String = jsonEscape(s)
        override fun decode(s: String): String = jsonUnescape(s)
    };

    abstract fun encode(s: String): String
    abstract fun decode(s: String): String

    companion object {
        fun fromTag(tag: String): Encoding? = entries.firstOrNull { it.tag == tag }

        /** Parse a `|`-suffix chain such as `b64,u` into [BASE64, URL] (innermost-first). */
        fun parseChain(raw: String?): List<Encoding> {
            if (raw.isNullOrBlank()) return emptyList()
            return raw.split(",").mapNotNull { fromTag(it.trim()) }
        }

        fun chainTag(chain: List<Encoding>): String = chain.joinToString(",") { it.tag }
    }
}

/** Apply the encoding chain (innermost-first) to turn a real value into its literal form. */
fun List<Encoding>.applyEncode(value: String): String {
    var v = value
    for (enc in this) v = enc.encode(v)
    return v
}

/** Reverse an encoding chain to recover the raw value from a literal (outermost-first peel). */
fun List<Encoding>.applyDecode(literal: String): String {
    var v = literal
    for (enc in this.asReversed()) v = enc.decode(v)
    return v
}

private fun jsonEscape(s: String): String {
    val sb = StringBuilder(s.length + 8)
    for (c in s) {
        when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            '\b' -> sb.append("\\b")
            '' -> sb.append("\\f")
            else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
    }
    return sb.toString()
}

private fun jsonUnescape(s: String): String {
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '\\' && i + 1 < s.length) {
            when (val n = s[i + 1]) {
                '"' -> sb.append('"')
                '\\' -> sb.append('\\')
                '/' -> sb.append('/')
                'n' -> sb.append('\n')
                'r' -> sb.append('\r')
                't' -> sb.append('\t')
                'b' -> sb.append('\b')
                'f' -> sb.append('')
                'u' -> {
                    if (i + 5 < s.length) {
                        val hex = s.substring(i + 2, i + 6)
                        sb.append(hex.toInt(16).toChar())
                        i += 4
                    } else sb.append(n)
                }

                else -> sb.append(n)
            }
            i += 2
        } else {
            sb.append(c)
            i++
        }
    }
    return sb.toString()
}
