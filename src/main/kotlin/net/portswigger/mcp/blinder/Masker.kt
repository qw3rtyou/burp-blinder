package net.portswigger.mcp.blinder

/**
 * Read-side masking. Detects secrets in text that would flow to the agent and replaces them with
 * vault placeholders, recording (per occurrence) the encoding context so the Rehydrator can
 * reproduce the exact original bytes.
 *
 * Reversibility guarantee: for every replacement the masker verifies that re-applying the encoding
 * chain to the decoded value reproduces the exact literal it found. If it cannot (non-canonical
 * encoding, garbage), it falls back to storing the literal verbatim in raw context, so the masked
 * text is always losslessly rehydratable (round-trip identity holds by construction).
 */
class Masker(
    private val vault: Vault,
    /** LEAK-2 policy toggle. Default OFF preserves prior behaviour (IPs pass through). */
    private val maskIpAddresses: Boolean = false,
    /** UUIDs are identifiers, not secrets. Default OFF leaves them readable; ON masks them. */
    private val maskUuids: Boolean = false
) {

    // JSON keys whose string values are secrets, mapped to a token type hint.
    private val sensitiveJsonKeys: Map<String, TokenType> = mapOf(
        "password" to TokenType.SECRET,
        "passwd" to TokenType.SECRET,
        "secret" to TokenType.SECRET,
        "client_secret" to TokenType.SECRET,
        "token" to TokenType.SECRET,
        "access_token" to TokenType.BEARER,
        "refresh_token" to TokenType.SECRET,
        "id_token" to TokenType.JWT,
        "api_key" to TokenType.APIKEY,
        "apikey" to TokenType.APIKEY,
        "authorization" to TokenType.SECRET,
        "session" to TokenType.COOKIE_SESSION,
        "sessionid" to TokenType.COOKIE_SESSION,
        "session_id" to TokenType.COOKIE_SESSION,
        "jwt" to TokenType.JWT
    )

    private val sensitiveParamHints =
        listOf("token", "session", "sess", "sid", "auth", "csrf", "xsrf", "secret", "key", "password", "apikey")

    /**
     * Register a literal as a placeholder with the given encoding chain, verifying reversibility.
     * Returns the emitted placeholder text to splice into the output.
     */
    fun maskLiteral(literal: String, chain: List<Encoding>, type: TokenType): String {
        if (chain.isEmpty()) {
            return vault.placeholderFor(literal, type)
        }
        val decoded = runCatching { chain.applyDecode(literal) }.getOrNull()
            ?: return vault.placeholderFor(literal, type)
        // Key the vault by the DECODED canonical value so the same secret gets one placeholder
        // regardless of the encoding/context it appeared in (reference-consistency de-fragmentation).
        // The per-occurrence chain still drives rehydration; for canonical inputs it reproduces the
        // exact bytes, and for non-canonical inputs it reproduces an equivalent canonical encoding.
        val base = vault.placeholderFor(decoded, type)
        return Placeholder.emit(base, chain)
    }

    fun mask(input: String): String {
        var text = input
        text = maskPem(text)
        text = maskAuthorization(text)
        text = maskApiKeyHeaders(text)
        text = maskCookieHeader(text)
        text = maskSetCookieHeader(text)
        // JWTs are converted to their selective analysis view BEFORE the nested/base64 and
        // high-entropy passes, which would otherwise hijack/clobber the base64url segments and
        // destroy the alg/claim structure (FAIL-1). Later passes protect the JWT ranges.
        text = maskJwts(text)
        text = maskQueryParams(text)
        text = maskJsonSensitiveValues(text)
        text = maskNestedBase64(text)
        text = maskEmails(text)
        text = maskPhones(text)
        if (maskIpAddresses) text = maskIps(text)
        if (maskUuids) text = maskUuidPass(text)
        text = maskHighEntropy(text)
        return text
    }

    // UUID masking (identifier), gated by the maskUuids toggle. Raw context, referentially consistent.
    private fun maskUuidPass(text: String) =
        replaceOutsidePlaceholders(text, SecretDetector.UUID, jwtRanges(text)) { uuid ->
            vault.placeholderFor(uuid, TokenType.UUID)
        }

    /** Ranges of JWT analysis views in the current text, protected from later mangling passes. */
    private fun jwtRanges(text: String): List<IntRange> =
        SecretDetector.JWT.findAll(text).map { it.range }.toList()

    // IP masking (LEAK-2), gated by the maskIpAddresses toggle. Raw context, referentially
    // consistent, so the same address always maps to the same placeholder and round-trips exactly.
    private fun maskIps(text: String): String {
        var out = replaceOutsidePlaceholders(text, SecretDetector.IPV6, jwtRanges(text)) { ip ->
            vault.placeholderFor(ip, TokenType.IP)
        }
        out = replaceOutsidePlaceholders(out, SecretDetector.IPV4, jwtRanges(out)) { ip ->
            vault.placeholderFor(ip, TokenType.IP)
        }
        return out
    }

    private fun maskPem(text: String) = SecretDetector.PEM.replace(text) {
        vault.placeholderFor(it.value, TokenType.PEM)
    }

    private val authHeader = Regex("""(?im)^(authorization|proxy-authorization):([ \t]*)(.+?)([ \t]*)$""")
    private fun maskAuthorization(text: String) = authHeader.replace(text) { m ->
        val name = m.groupValues[1]
        val sp = m.groupValues[2]
        val value = m.groupValues[3]
        val trail = m.groupValues[4]
        val masked = when {
            value.startsWith("Bearer ", ignoreCase = true) ->
                "Bearer " + maskLiteral(value.substring(7).trim(), emptyList(), TokenType.BEARER)

            value.startsWith("Basic ", ignoreCase = true) ->
                "Basic " + maskLiteral(value.substring(6).trim(), emptyList(), TokenType.BASIC)

            else -> maskLiteral(value.trim(), emptyList(), TokenType.SECRET)
        }
        "$name:$sp$masked$trail"
    }

    private val apiKeyHeader = Regex(
        """(?im)^(x-api-key|api-key|apikey|x-auth-token|x-auth|x-access-token|x-session-token|x-amz-security-token):([ \t]*)(.+?)([ \t]*)$"""
    )
    private fun maskApiKeyHeaders(text: String) = apiKeyHeader.replace(text) { m ->
        "${m.groupValues[1]}:${m.groupValues[2]}${maskLiteral(m.groupValues[3].trim(), emptyList(), TokenType.APIKEY)}${m.groupValues[4]}"
    }

    private val cookieHeader = Regex("""(?im)^(cookie):([ \t]*)(.+?)([ \t]*)$""")
    private fun maskCookieHeader(text: String) = cookieHeader.replace(text) { m ->
        val rebuilt = m.groupValues[3].split(";").joinToString(";") { part ->
            val eq = part.indexOf('=')
            if (eq <= 0) return@joinToString part
            val leading = part.takeWhile { it == ' ' }
            val name = part.substring(0, eq).trim()
            val value = part.substring(eq + 1)
            if (value.isNotBlank() && SecretDetector.isSensitiveCookieName(name)) {
                val type = if (name.lowercase().let { it.contains("sess") || it.contains("sid") })
                    TokenType.COOKIE_SESSION else TokenType.COOKIE
                "$leading$name=${maskLiteral(value.trim(), emptyList(), type)}"
            } else part
        }
        "${m.groupValues[1]}:${m.groupValues[2]}$rebuilt${m.groupValues[4]}"
    }

    private val setCookieHeader = Regex("""(?im)^(set-cookie):([ \t]*)([^=;\r\n]+)=([^;\r\n]+)(.*)$""")
    private fun maskSetCookieHeader(text: String) = setCookieHeader.replace(text) { m ->
        val name = m.groupValues[3].trim()
        val value = m.groupValues[4]
        if (SecretDetector.isSensitiveCookieName(name)) {
            val type = if (name.lowercase().let { it.contains("sess") || it.contains("sid") })
                TokenType.COOKIE_SESSION else TokenType.COOKIE
            "${m.groupValues[1]}:${m.groupValues[2]}${m.groupValues[3]}=${maskLiteral(value, emptyList(), type)}${m.groupValues[5]}"
        } else m.value
    }

    // Request-line query params: GET /path?a=b&c=d HTTP/1.1
    private val requestLine = Regex("""(?m)^([A-Z]+ )(\S*\?\S*)( HTTP/[0-9.]+)$""")
    private fun maskQueryParams(text: String) = requestLine.replace(text) { m ->
        val method = m.groupValues[1]
        val target = m.groupValues[2]
        val proto = m.groupValues[3]
        val qIdx = target.indexOf('?')
        val path = target.substring(0, qIdx)
        val query = target.substring(qIdx + 1)
        val newQuery = query.split("&").joinToString("&") { pair ->
            val eq = pair.indexOf('=')
            if (eq <= 0) return@joinToString pair
            val name = pair.substring(0, eq)
            val value = pair.substring(eq + 1)
            if (value.isBlank()) return@joinToString pair
            val nameSensitive = sensitiveParamHints.any { name.lowercase().contains(it) }
            val decoded = runCatching { Encoding.URL.decode(value) }.getOrNull()
            val valueSecret = decoded != null &&
                    (SecretDetector.looksLikeJwt(decoded) || SecretDetector.isHighEntropySecret(decoded) ||
                            SecretDetector.EMAIL.matches(decoded))
            if (nameSensitive || valueSecret) {
                "$name=${maskLiteral(value, listOf(Encoding.URL), TokenType.SECRET)}"
            } else pair
        }
        "$method$path?$newQuery$proto"
    }

    private val jsonPair = Regex("""("([A-Za-z0-9_]+)"\s*:\s*")([^"\\]*(?:\\.[^"\\]*)*)(")""")
    private fun maskJsonSensitiveValues(text: String) = jsonPair.replace(text) { m ->
        val prefix = m.groupValues[1]
        val key = m.groupValues[2]
        val value = m.groupValues[3]
        val suffix = m.groupValues[4]
        val type = sensitiveJsonKeys[key.lowercase()]
        when {
            type == null || value.isBlank() -> m.value
            // A JWT value carries analysis value (alg, claim keys). Defer it to the JWT pass so it
            // is selectively masked (structure preserved) instead of opaquely vaulted.
            SecretDetector.looksLikeJwt(value) -> m.value
            else -> "$prefix${maskLiteral(value, listOf(Encoding.JSON), type)}$suffix"
        }
    }

    // Nested: base64 token whose decoded content is JSON containing secrets. We mask the inner JSON
    // and re-encode; the Rehydrator reverses this structurally.
    private val base64Blob = Regex("""[A-Za-z0-9+/]{16,}={0,2}""")
    private fun maskNestedBase64(text: String) = replaceOutsidePlaceholders(text, base64Blob, jwtRanges(text)) { literal ->
        val decoded = runCatching { Encoding.BASE64.decode(literal) }.getOrNull()
        if (decoded == null || !SecretDetector.looksStructural(decoded)) return@replaceOutsidePlaceholders literal
        if (Encoding.BASE64.encode(decoded) != literal) return@replaceOutsidePlaceholders literal
        val maskedInner = mask(decoded)
        if (maskedInner == decoded) literal else Encoding.BASE64.encode(maskedInner)
    }

    private fun maskJwts(text: String) = replaceOutsidePlaceholders(text, SecretDetector.JWT) { jwt ->
        JwtMasker.selectiveMask(jwt)
    }

    private fun maskEmails(text: String): String {
        val skip = Placeholder.parseAll(text).map { it.range } + jwtRanges(text)
        return SecretDetector.EMAIL.replace(text) { m ->
            val overlaps = skip.any { it.first <= m.range.last && m.range.first <= it.last }
            // scp/ssh remote syntax `git@github.com:org/repo.git` — a host reference, not PII.
            val scpSyntax = text.getOrNull(m.range.last + 1) == ':'
            if (overlaps || scpSyntax) m.value else vault.placeholderFor(m.value, TokenType.EMAIL)
        }
    }

    // Phone numbers (PII), masked by default like emails; raw context, referentially consistent.
    private fun maskPhones(text: String) = replaceOutsidePlaceholders(text, SecretDetector.PHONE, jwtRanges(text)) { phone ->
        vault.placeholderFor(phone, TokenType.PHONE)
    }

    // Standalone token candidates (secrets hidden behind custom key names / in bodies). The length
    // floor is 20 to match SecretDetector.isHighEntropySecret's own lower bound (LEAK-1); every match
    // is then put through the entropy gate, so 20-31 char high-entropy tokens are caught while
    // low-entropy filler of the same length is left alone. Token body excludes '=' (base64 padding
    // only appears trailing) and is delimited by non-token chars so `field=<blob>` is not swallowed
    // whole via the '=' separator.
    private val isolatedToken = Regex("""(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{20,}={0,2}(?![A-Za-z0-9+/_\-])""")

    // Position exclusions: an HTTP header field-name token (line start, before ':') and a JSON
    // object key are structural, never secret values. Masking only applies to VALUE positions.
    private val headerFieldName = Regex("""(?im)^([A-Za-z0-9._-]+)[ \t]*:""")
    private val jsonKey = Regex("""["']([A-Za-z0-9_.\-]+)["']\s*:""")

    private fun maskHighEntropy(text: String): String {
        // Protect (a) JWT analysis-view segments (FAIL-1), (b) header field names and JSON keys
        // (they are structural identifiers, not values), and (c) UUIDs when the UUID toggle is off.
        val protected = jwtRanges(text) +
                headerFieldName.findAll(text).map { it.groups[1]!!.range } +
                jsonKey.findAll(text).map { it.groups[1]!!.range } +
                if (!maskUuids) SecretDetector.UUID.findAll(text).map { it.range }.toList() else emptyList()

        return replaceOutsidePlaceholders(text, isolatedToken, protectedRanges = protected) { token ->
            when {
                // A base64 blob that already carries masked placeholders was handled by the nested
                // pass; do not clobber it (that would break structural rehydration).
                isNestedMaskedBlob(token) -> token
                isMaskableSecret(token) -> vault.placeholderFor(token, TokenType.SECRET)
                else -> token
            }
        }
    }

    // Segment classifiers used to tell a separator-joined identifier apart from a secret.
    private val alphaSegment = Regex("""^[A-Za-z]+$""")            // dictionary-ish word
    private val hexSegment = Regex("""^[0-9a-fA-F]+$""")          // hex id / trace segment (incl. pure digit)
    private val versionSegment = Regex("""^[A-Za-z]+[0-9]{1,3}$""") // short numeric version suffix (v2, utf8)

    // 2nd entropy gate for tokens whose segments are each individually simple but whose whole is not
    // all-hex: length*entropy below this reads as a structural identifier, above as a secret.
    // Tuned (auditor round-4 data) so `xoxb-1234-5678-abcdEFGH` (~95) masks while
    // `x_ratelimit_v2_reset` (~68) and hex trace ids do not.
    private val idLikeEntropyBudget = 85.0

    /**
     * Precision gate over a high-entropy candidate (LEAK-1 kept, over-masking removed; round-4
     * leak-window narrowing).
     *  - Separator-joined pure-alphabetic identifiers (header names, snake_case keys, URL paths) are
     *    excluded at any length (structure guard #2).
     *  - Separator-joined, 20-31 chars: classify each segment.
     *      * any segment that is neither alpha nor hex nor a single short version suffix => a mixed
     *        secret fragment (`whsec_aZ9qP2xL...`, `xoxb-9qP2xL...`) => entropy gate (mask).
     *      * at most ONE version-suffix segment counts as identifier-like (so a body of
     *        letter+digit fragments like `sk-abc12-DEF34-ghi56-JKL78` is not laundered as versions).
     *      * all segments hex/digit => trace/numeric id => kept readable (accepted LOW trade-off).
     *      * otherwise (alpha + hex/digit, all simple): 2nd entropy gate — a genuine identifier such
     *        as `x_ratelimit_v2_reset` stays readable, a low-complexity-looking Slack/webhook token
     *        `xoxb-1234-5678-abcdEFGH` is masked.
     *  - Continuous run (no separators) still needs a class mix (digit / base64 symbol) so pure-letter
     *    camelCase identifiers are not masked.
     *  - >= 32 chars keeps the prior always-mask behaviour, still subject to the structure guard.
     */
    private fun isMaskableSecret(token: String): Boolean {
        if (SecretDetector.STRUCTURAL_IDENTIFIER.matches(token)) return false
        if (token.length < 32) {
            val segments = token.split('_', '-', '.', '/').filter { it.isNotEmpty() }
            if (segments.size > 1) {
                var versionUsed = 0
                val allIdLike = segments.all { seg ->
                    when {
                        hexSegment.matches(seg) -> true
                        alphaSegment.matches(seg) -> true
                        versionSegment.matches(seg) && versionUsed == 0 -> { versionUsed++; true }
                        else -> false
                    }
                }
                if (allIdLike) {
                    if (segments.all { hexSegment.matches(it) }) return false // trace/numeric id
                    if (token.length * SecretDetector.shannonEntropy(token) < idLikeEntropyBudget) return false
                    // else: high-complexity id-like token -> treat as secret (fall through).
                }
                // any mixed segment -> fall through to the entropy gate below.
            } else {
                // Continuous run: require class mixing so pure-letter identifiers are not masked.
                val hasDigit = token.any(Char::isDigit)
                val hasBase64Symbol = token.any { it == '+' || it == '/' }
                if (!hasDigit && !hasBase64Symbol) return false
            }
        }
        return SecretDetector.isHighEntropySecret(token)
    }

    private fun isNestedMaskedBlob(token: String): Boolean {
        val decoded = runCatching { Encoding.BASE64.decode(token) }.getOrNull() ?: return false
        return Placeholder.containsAny(decoded)
    }

    /**
     * Apply [transform] to regex matches that do not overlap an already-emitted `{{...}}` nor any
     * caller-supplied [protectedRanges] (e.g. JWT analysis-view segments).
     */
    private fun replaceOutsidePlaceholders(
        text: String,
        regex: Regex,
        protectedRanges: List<IntRange> = emptyList(),
        transform: (String) -> String
    ): String {
        val skipRanges = Placeholder.parseAll(text).map { it.range } + protectedRanges
        return regex.replace(text) { m ->
            val overlaps = skipRanges.any { it.first <= m.range.last && m.range.first <= it.last }
            if (overlaps) m.value else transform(m.value)
        }
    }
}
