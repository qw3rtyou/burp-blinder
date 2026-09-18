package net.portswigger.mcp.blinder

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Selective (minimum-necessary) masking for JWTs. The structure that carries analysis value is
 * preserved — the token is still a JWT, the header (`alg`, `typ`) is untouched, and every claim
 * KEY stays visible — while only the sensitive claim VALUES are replaced with format-preserving
 * placeholders. This lets the agent reason about `alg=none`, claim shape and privilege fields
 * without learning the real identity.
 *
 * JWTs are signed, so byte-exact rehydration is out of v1 scope: this output is an analysis view,
 * not a value the gateway round-trips. A bearer token that must be resent verbatim is handled
 * separately by the Masker as an opaque `{{BEARER_n}}` vault placeholder.
 */
object JwtMasker {

    // Claim keys whose values identify a real principal / hold secrets.
    private val SENSITIVE_CLAIMS = setOf(
        "email", "sub", "name", "given_name", "family_name", "middle_name", "nickname",
        "preferred_username", "upn", "unique_name", "phone_number", "phone", "address",
        "sid", "jti", "azp", "at_hash", "c_hash", "nonce"
    )

    private val urlDecoder = Base64.getUrlDecoder()
    private val urlEncoder = Base64.getUrlEncoder().withoutPadding()
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Returns a JWT with sensitive claim values masked, or the original string unchanged if it
     * cannot be parsed as a JWT (fail-safe: an unparseable token is left to the generic detector).
     */
    fun selectiveMask(token: String, idFor: (TokenType) -> Int = counter()): String {
        val parts = token.split(".")
        if (parts.size != 3) return token
        return try {
            val payloadJson = decodeSegment(parts[1])
            val payload = json.parseToJsonElement(payloadJson).jsonObject
            val masked = maskClaims(payload, idFor)
            val newPayload = urlEncoder.encodeToString(
                json.encodeToString(JsonObject.serializer(), masked).toByteArray(StandardCharsets.UTF_8)
            )
            "${parts[0]}.$newPayload.SIGNATURE_MASKED"
        } catch (_: Exception) {
            token
        }
    }

    private fun maskClaims(payload: JsonObject, idFor: (TokenType) -> Int): JsonObject {
        val result = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()
        for ((key, value) in payload) {
            if (key.lowercase() in SENSITIVE_CLAIMS && value is JsonPrimitive && value.isString) {
                result[key] = JsonPrimitive(maskValue(key, value.content, idFor))
            } else {
                result[key] = value
            }
        }
        return JsonObject(result)
    }

    private fun maskValue(key: String, value: String, idFor: (TokenType) -> Int): String {
        return if (SecretDetector.EMAIL.matches(value)) {
            "masked${idFor(TokenType.EMAIL)}@blinded.invalid"
        } else {
            "MASKED_${key.uppercase()}_${idFor(TokenType.SECRET)}"
        }
    }

    private fun decodeSegment(seg: String): String =
        String(urlDecoder.decode(seg), StandardCharsets.UTF_8)

    private fun counter(): (TokenType) -> Int {
        val counters = HashMap<TokenType, Int>()
        return { t -> (counters[t] ?: 0).let { counters[t] = it + 1; it + 1 } }
    }
}
