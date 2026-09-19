package net.portswigger.mcp.blinder

import kotlin.math.ln

/**
 * Detection is intentionally biased: a false negative (a leaked secret) is far worse than a false
 * positive (over-masking). Boundary cases are masked. Detection combines key-name knowledge with
 * value-shape heuristics so custom key names cannot hide a secret.
 */
object SecretDetector {

    // Shape-based patterns.
    val EMAIL = Regex("""[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}""")

    // JWT: three base64url segments, header starts with eyJ (`{"`).
    val JWT = Regex("""eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+""")

    // PEM private/certificate blocks (multiline).
    val PEM = Regex(
        """-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----"""
    )

    // A run that looks like base64/hex/token material of meaningful length.
    val TOKEN_CANDIDATE = Regex("""[A-Za-z0-9+/=_\-]{20,}""")

    // UUID (canonical 8-4-4-4-12 hex). An identifier, not a secret; masked only under a toggle.
    val UUID = Regex("""\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""")

    // MAC address (6 hex octets, `:` or `-` separated). Identifier; masked only in STRICT mode.
    val MAC = Regex("""\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b""")

    // Separator-joined alphabetic word list (HTTP header names, snake_case JSON keys, URL paths).
    // These are structural identifiers, never secrets, regardless of length/entropy. Leading,
    // trailing and repeated `-_./` separators are allowed so a request-line path like
    // `/repos/PortSwigger/mcp-server` (leading slash) is still recognised.
    val STRUCTURAL_IDENTIFIER = Regex("""^[-_./]*[A-Za-z]+(?:[-_./]+[A-Za-z]+)*[-_./]*$""")

    // Phone numbers (PII, masked by default like emails). E.164 with optional country-code
    // separator (`+81 90...`, `+14155552671`), or a separator-grouped national form with optional
    // extension. Requiring separators/`+` avoids tripping on continuous digit runs (timestamps/ids).
    val PHONE = Regex(
        """(?<![\d+])(?:""" +
            """\+\d{1,3}[-.\s]?\(?\d{2,4}\)?(?:[-.\s]?\d{2,4}){1,4}""" +  // +CC then grouped/contiguous national (+81 90..., +1 (415) 555-2671, +44-20-7946-0958)
            """|\+\d{6,15}""" +                                            // bare E.164 contiguous
            """|\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}(?:\s?(?:[xX]|ext\.?)\s?\d{1,7})?""" +  // (area)-code form ((254)954-1289, (800) 555 0199, (775)976-6794 x41206)
            """|(?:\d{1,3}[-.\s])?\d{3}[-.\s]\d{3}[-.\s]\d{4}(?:\s?[xX]\d{1,7})?""" +  // national grouped 3-3-4 + optional extension
            """)(?!\d)"""
    )

    // Credit-card-shaped candidate: 13-19 digits with optional single space/hyphen separators.
    // A candidate is only a card if it also passes the Luhn checksum (see luhnValid) — this keeps
    // random 16-digit ids/timestamps unmasked while catching real PANs.
    val CARD_CANDIDATE = Regex("""(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])""")

    // US SSN standard shape 3-2-4. Non-standard national-id shapes are caught by key name instead.
    val SSN = Regex("""(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)""")

    // Connection-string / URI userinfo `//user:password@host`. Requires the `//` authority marker
    // and a trailing `@`, so `http://host/a:b` (path colon, no userinfo) does not match. Group 1 is
    // the user, group 2 the password (masked). Works for postgres/mysql(jdbc)/mongodb/redis/amqp/ftp.
    val URI_CREDENTIALS = Regex("""//([^\s:/@]+):([^\s/@]+)@""")

    /** Luhn (mod-10) checksum over the digits of a card candidate. */
    fun luhnValid(digits: String): Boolean {
        if (digits.length !in 13..19 || digits.any { !it.isDigit() }) return false
        var sum = 0
        var alt = false
        for (i in digits.indices.reversed()) {
            var d = digits[i] - '0'
            if (alt) {
                d *= 2
                if (d > 9) d -= 9
            }
            sum += d
            alt = !alt
        }
        return sum % 10 == 0
    }

    // IPv4 (dotted quad, each octet 0-255) and IPv6 (must contain ':'; covers compressed `::` forms).
    val IPV4 = Regex("""\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b""")
    // Comprehensive IPv6: a full 8-group address OR any `::`-compressed form. Deliberately does NOT
    // match a bare `HH:MM:SS` clock time (3 groups, no `::`), so IP masking and time preservation no
    // longer overlap (LOW-1). Bounded so it consumes a whole address, including trailing groups.
    val IPV6 = Regex(
        "(?<![0-9A-Fa-f:.])(?:" +
            "(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}" +
            "|(?:[0-9A-Fa-f]{1,4}:){1,7}:" +
            "|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}" +
            "|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}" +
            "|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}" +
            "|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}" +
            "|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}" +
            "|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}" +
            "|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)" +
            ")(?![0-9A-Fa-f:.])"
    )

    // Sensitive cookie names (case-insensitive substring match).
    private val SENSITIVE_COOKIE_HINTS = listOf(
        "session", "sess", "sid", "auth", "token", "jwt", "secret", "csrf", "xsrf", "phpsessid",
        "jsessionid", "asp.net", "remember", "access", "refresh"
    )

    // Header names whose values are always credentials.
    private val CREDENTIAL_HEADERS = listOf(
        "authorization", "proxy-authorization", "x-api-key", "api-key", "apikey",
        "x-auth-token", "x-auth", "x-access-token", "x-session-token", "x-amz-security-token",
        "cookie", "set-cookie"
    )

    fun looksLikeJwt(s: String): Boolean = JWT.matches(s.trim())

    fun isSensitiveCookieName(name: String): Boolean {
        val n = name.lowercase()
        return SENSITIVE_COOKIE_HINTS.any { n.contains(it) }
    }

    fun isCredentialHeader(name: String): Boolean = name.trim().lowercase() in CREDENTIAL_HEADERS

    /**
     * High-entropy secret heuristic: long enough, mostly token charset, and enough randomness.
     * Deliberately lenient (masks more) for tokens >= 32 chars.
     */
    fun isHighEntropySecret(s: String): Boolean {
        val v = s.trim()
        if (v.length < 20) return false
        if (!TOKEN_CANDIDATE.matches(v)) return false
        // Very long token-charset strings are almost certainly secrets.
        if (v.length >= 32) return true
        return shannonEntropy(v) >= 3.5
    }

    fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>()
        for (c in s) freq[c] = (freq[c] ?: 0) + 1
        val len = s.length.toDouble()
        var e = 0.0
        for (count in freq.values) {
            val p = count / len
            e -= p * (ln(p) / ln(2.0))
        }
        return e
    }

    /** True if a decoded string is worth recursing into (JSON object/array or nested token). */
    fun looksStructural(s: String): Boolean {
        val t = s.trim()
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))
    }
}
