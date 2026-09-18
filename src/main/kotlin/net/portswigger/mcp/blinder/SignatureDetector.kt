package net.portswigger.mcp.blinder

/**
 * Signed requests (HMAC body signatures, AWS SigV4, OAuth 1.0a, webhook signatures) break if we
 * substitute real values after the client computed the signature over the placeholder text. v1
 * excludes them: when a request looks signed the gateway skips rehydration and logs "signed request
 * - unsupported" rather than silently emitting a request whose signature no longer matches its body.
 *
 * Detection is deliberately narrow (FAIL-2): a bare `sig`/`signature`/`hmac` FIELD is not enough to
 * declare a request signed, because normal requests carry such fields. We require either a signature
 * HEADER in the request prelude, an unambiguous scheme marker (SigV4 / OAuth 1.0a), or a
 * signature-shaped VALUE (long hex/base64) attached to a signature field.
 */
object SignatureDetector {

    // Header names that only appear on signed requests. Matched in the prelude (before the body).
    private val SIGNATURE_HEADERS = listOf(
        "x-signature", "x-hub-signature", "x-hub-signature-256", "x-amz-content-sha256",
        "x-goog-signature", "x-slack-signature", "x-webhook-signature", "signature",
        "x-signed", "x-content-signature"
    )

    // Unambiguous scheme markers (their mere presence implies a signature we cannot recompute).
    private val STRONG_NAME_MARKERS = listOf("aws4-hmac-sha256", "oauth_signature")

    // A signature field whose VALUE is a real signature shape: >=40 hex, or >=40 base64/base64url.
    private val SIGNATURE_VALUED_FIELD = Regex(
        """(?i)\b(x-hub-signature(?:-256)?|hmac|signature|sig|mac)"?\s*[:=]\s*"?""" +
            """(?:sha\d{0,3}=)?(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9+/\-_]{40,}={0,2})"""
    )

    fun isSigned(rawRequest: String): Boolean {
        val lower = rawRequest.lowercase()
        if (STRONG_NAME_MARKERS.any { lower.contains(it) }) return true

        val prelude = preludeOf(rawRequest)
        if (SIGNATURE_HEADERS.any { header -> Regex("(?im)^$header[ \t]*:").containsMatchIn(prelude) }) return true

        // Body/query signature field, only when the value actually looks like a signature.
        return SIGNATURE_VALUED_FIELD.containsMatchIn(rawRequest)
    }

    private fun preludeOf(raw: String): String {
        val markers = listOf("\r\n\r\n", "\n\n")
        val idx = markers.mapNotNull { m -> raw.indexOf(m).takeIf { it >= 0 } }.minOrNull()
        return if (idx == null) raw else raw.substring(0, idx)
    }
}
