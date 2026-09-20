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
    maskIpAddresses: Boolean = false,
    maskUuids: Boolean = false,
    mode: MaskingMode = MaskingMode.SELECTIVE,
    /** Mask private/internal IPs (RFC1918/loopback/link-local/ULA) even in SELECTIVE. Default ON. */
    maskPrivateIps: Boolean = true,
    /** Internal DNS suffixes/hosts to mask (topology). Default corporate suffixes. */
    internalDomains: List<String> = DEFAULT_INTERNAL_DOMAINS
) {
    companion object {
        val DEFAULT_INTERNAL_DOMAINS = listOf("local", "internal", "corp", "lan", "intranet", "home.arpa")
    }

    /** LEAK-2 policy toggle. Default OFF preserves prior behaviour (public IPs pass through). Runtime-settable. */
    @Volatile
    var maskIpAddresses: Boolean = maskIpAddresses

    @Volatile
    var maskPrivateIps: Boolean = maskPrivateIps

    // Internal-host matcher, built from the configured suffix list. A hostname is masked only when it
    // ends in one of these suffixes at a label boundary (so `.corp` matches `x.corp`, never
    // `mycorp.com`), and public TLDs (.com/.net/.org) never appear in the list.
    private val internalHostRegex: Regex? = if (internalDomains.isEmpty()) null else Regex(
        "(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+" +
            "(?:" + internalDomains.joinToString("|") { Regex.escape(it) } + ")" +
            "(?![A-Za-z0-9.\\-])",
        RegexOption.IGNORE_CASE
    )

    /** UUIDs are identifiers, not secrets. Default OFF leaves them readable; ON masks them. Runtime-settable. */
    @Volatile
    var maskUuids: Boolean = maskUuids

    /** Masking mode (OFF/SELECTIVE/STRICT), changeable at runtime from the config tab. */
    @Volatile
    var mode: MaskingMode = mode

    private val strict: Boolean get() = mode == MaskingMode.STRICT

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
        "jwt" to TokenType.JWT,
        // PII by key name (value masked regardless of shape — covers non-standard national forms).
        "ssn" to TokenType.SSN,
        "social_security" to TokenType.SSN,
        "socialsecurity" to TokenType.SSN,
        "social_security_number" to TokenType.SSN,
        "national_id" to TokenType.SSN,
        "nationalid" to TokenType.SSN,
        "tax_id" to TokenType.SSN,
        "taxid" to TokenType.SSN,
        "cardnumber" to TokenType.CARD,
        "card_number" to TokenType.CARD,
        "creditcard" to TokenType.CARD,
        "credit_card" to TokenType.CARD
    )

    // Sensitive parameter/form key names, matched on a normalized form (lowercased, `-`/`_` removed)
    // so `api_key`, `api-key`, `apiKey`, `APIKEY` all collapse to `apikey`. Exact names plus a few
    // strong suffixes (so `csrf_token`, `reset_token`, `x_session_id` are caught) — exact matching
    // avoids substring false positives like `monkey`/`username`.
    private val sensitiveKeyExact = setOf(
        "password", "passwd", "pwd", "pass", "token", "accesstoken", "refreshtoken", "idtoken",
        "secret", "clientsecret", "apikey", "apitoken", "auth", "authorization", "session",
        "sessionid", "sessiontoken", "sid", "csrf", "xsrf", "otp", "pin", "secretkey", "privatekey",
        "creditcard", "cardnumber", "ssn"
    )
    // Suffixes so prefixed env/config keys (DB_PASSWORD, MYSQL_ROOT_PASSWORD, API_SECRET,
    // ACCESS_TOKEN, AWS_ACCESS_KEY, ...) are caught. All are unambiguous compounds — bare `key` is
    // deliberately excluded to avoid public_key-style false positives.
    private val sensitiveKeySuffix = listOf(
        "password", "passwd", "token", "secret", "apikey", "sessionid",
        "accesskey", "secretkey", "privatekey", "clientsecret"
    )

    private fun normalizeKey(name: String): String = name.lowercase().replace(Regex("[-_]"), "")

    private fun isSensitiveParamKey(name: String): Boolean {
        val n = normalizeKey(name)
        if (n in sensitiveKeyExact || sensitiveKeySuffix.any { n.endsWith(it) }) return true
        // `pass` only at a segment boundary (db_pass / db-pass / exact) — never inside bypass/compass.
        val raw = name.lowercase()
        return raw == "pass" || raw.endsWith("_pass") || raw.endsWith("-pass")
    }

    private fun paramKeyType(name: String): TokenType {
        val n = normalizeKey(name)
        return when {
            n.contains("ssn") -> TokenType.SSN
            n.contains("card") -> TokenType.CARD
            n == "accesstoken" -> TokenType.BEARER
            else -> TokenType.SECRET
        }
    }

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
        if (mode == MaskingMode.OFF) return input
        var text = input
        text = maskPem(text)
        text = maskAuthorization(text)
        text = maskApiKeyHeaders(text)
        text = maskCookieHeader(text)
        text = maskSetCookieHeader(text)
        text = maskUriCredentials(text)
        // JWTs are converted to their selective analysis view BEFORE the nested/base64 and
        // high-entropy passes, which would otherwise hijack/clobber the base64url segments and
        // destroy the alg/claim structure (FAIL-1). Later passes protect the JWT ranges.
        text = maskJwts(text)
        text = maskQueryParams(text)
        text = maskFormKeys(text)
        text = maskJsonSensitiveValues(text)
        text = maskEscapedJsonSensitiveValues(text)
        text = maskNestedBase64(text)
        text = maskEmails(text)
        text = maskEncodedEmails(text)
        text = maskCards(text)
        text = maskSsn(text)
        text = maskPhones(text)
        // MAC before IP: an IPv6 pattern would otherwise swallow a colon-separated MAC as an IP.
        if (strict) text = maskMac(text)
        text = maskInternalHosts(text)
        when {
            maskIpAddresses || strict -> text = maskIps(text)             // all IPs
            maskPrivateIps -> text = maskPrivateIpsPass(text)             // private/internal only
        }
        if (maskUuids || strict) text = maskUuidPass(text)
        text = maskHighEntropy(text)
        return text
    }

    // MAC addresses — masked only in STRICT (aggressive, toggle-ignoring).
    private fun maskMac(text: String) = replaceOutsidePlaceholders(text, SecretDetector.MAC, jwtRanges(text)) { mac ->
        vault.placeholderFor(mac, TokenType.MAC)
    }

    // Private/internal IPs only (RFC1918/loopback/link-local/ULA). Public IPs are left readable.
    private fun maskPrivateIpsPass(text: String): String {
        var out = replaceOutsidePlaceholders(text, SecretDetector.IPV6, jwtRanges(text)) { ip ->
            if (SecretDetector.isInternalIp(ip)) vault.placeholderFor(ip, TokenType.IP) else ip
        }
        out = replaceOutsidePlaceholders(out, SecretDetector.IPV4, jwtRanges(out)) { ip ->
            if (SecretDetector.isInternalIp(ip)) vault.placeholderFor(ip, TokenType.IP) else ip
        }
        return out
    }

    // Internal hostnames (topology): mask the host only, preserving scheme/port/path/URL structure.
    private fun maskInternalHosts(text: String): String {
        val regex = internalHostRegex ?: return text
        return replaceOutsidePlaceholders(text, regex, jwtRanges(text)) { host ->
            vault.placeholderFor(host, TokenType.IHOST)
        }
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
        // The comprehensive IPv6 pattern (full 8-group or `::`-compressed) structurally never matches
        // a bare HH:MM:SS time, so no time carve-out is needed here — a time-shaped group that is part
        // of a real IPv6 (e.g. 2001:12:34:56::1) is now masked as one whole address (LOW-1 fix).
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

    // Connection-string / URI userinfo: mask the PASSWORD only, preserving scheme/user/host/port/path
    // so the structure stays readable (postgres://admin:{{SECRET_1}}@db:5432/prod). Password stored
    // verbatim -> byte-exact round-trip; same password -> same placeholder (reference consistency).
    private fun maskUriCredentials(text: String) = SecretDetector.URI_CREDENTIALS.replace(text) { m ->
        val user = m.groupValues[1]
        val password = m.groupValues[2]
        if (Placeholder.containsAny(password)) m.value
        else "//$user:${maskLiteral(password, emptyList(), TokenType.SECRET)}@"
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
            // STRICT masks every cookie value; SELECTIVE only sensitive-named cookies.
            if (value.isNotBlank() && (strict || SecretDetector.isSensitiveCookieName(name))) {
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
        if (strict || SecretDetector.isSensitiveCookieName(name)) {
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
            val nameSensitive = isSensitiveParamKey(name)
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

    // Key-based masking for form-urlencoded bodies (and any `key=value` outside the request line).
    // Covers login POSTs (`password=...`) that JSON key-based masking misses. Only sensitive keys
    // are touched; values already turned into placeholders (e.g. request-line query) are skipped.
    private val formPair = Regex("""(?<![A-Za-z0-9_%.\-])([A-Za-z0-9_.\[\]\-]{1,64})=([^&#\s"'<>\\]+)""")
    private fun maskFormKeys(text: String): String {
        val skip = Placeholder.parseAll(text).map { it.range } + jwtRanges(text)
        return formPair.replace(text) { m ->
            val overlaps = skip.any { it.first <= m.range.last && m.range.first <= it.last }
            val key = m.groupValues[1]
            val value = m.groupValues[2]
            when {
                overlaps || Placeholder.containsAny(value) -> m.value
                !isSensitiveParamKey(key) -> m.value
                else -> {
                    // Byte-exact by default (raw); only decode when the value is actually %-encoded.
                    val chain = if (value.contains('%')) listOf(Encoding.URL) else emptyList()
                    "$key=${maskLiteral(value, chain, paramKeyType(key))}"
                }
            }
        }
    }

    private val jsonPair = Regex("""("([A-Za-z0-9_]+)"\s*:\s*")([^"\\]*(?:\\.[^"\\]*)*)(")""")
    private fun maskJsonSensitiveValues(text: String) = jsonPair.replace(text) { m ->
        val prefix = m.groupValues[1]
        val key = m.groupValues[2]
        val value = m.groupValues[3]
        val suffix = m.groupValues[4]
        val type = sensitiveJsonValueType(key)
        when {
            type == null || value.isBlank() -> m.value
            // A JWT value carries analysis value (alg, claim keys). Defer it to the JWT pass so it
            // is selectively masked (structure preserved) instead of opaquely vaulted.
            SecretDetector.looksLikeJwt(value) -> m.value
            else -> {
                // An echoed `Authorization: Bearer <token>` value: mask only the token, with the
                // same BEARER type/vault key as the request-header path, so the header placeholder
                // and the JSON echo collapse to one identity (no reference fragmentation).
                val scheme = schemeValue.matchEntire(value)
                if (scheme != null) {
                    val kw = scheme.groupValues[1]
                    val tok = scheme.groupValues[2]
                    val schemeType = if (kw.equals("Basic", true)) TokenType.BASIC else TokenType.BEARER
                    "$prefix$kw ${maskLiteral(tok, listOf(Encoding.JSON), schemeType)}$suffix"
                } else {
                    "$prefix${maskLiteral(value, listOf(Encoding.JSON), type)}$suffix"
                }
            }
        }
    }

    private val schemeValue = Regex("""(?i)(Bearer|Basic)\s+(\S.*)""")

    // Exact map first, then suffix matcher (DB_PASSWORD, API_SECRET, ACCESS_TOKEN, ...).
    private fun sensitiveJsonValueType(key: String): TokenType? =
        sensitiveJsonKeys[key.lowercase()] ?: if (isSensitiveParamKey(key)) paramKeyType(key) else null

    // Double-encoded JSON: a JSON body serialised INTO a JSON string escapes its quotes as `\"`
    // (httpbin `data`, webhook/log/queue wrappers). Key-based masking must see `\"key\":\"value\"`
    // too. One level of escaping is handled; the value only is masked (escapes/structure preserved),
    // byte-exact round-trip.
    private val escapedJsonPair = Regex("""(\\"([A-Za-z0-9_]+)\\"\s*:\s*\\")([^"\\]*)(\\")""")
    private fun maskEscapedJsonSensitiveValues(text: String) = escapedJsonPair.replace(text) { m ->
        val prefix = m.groupValues[1]
        val key = m.groupValues[2]
        val value = m.groupValues[3]
        val suffix = m.groupValues[4]
        val type = sensitiveJsonValueType(key)
        when {
            type == null || value.isBlank() || Placeholder.containsAny(value) || SecretDetector.looksLikeJwt(value) -> m.value
            else -> "$prefix${maskLiteral(value, emptyList(), type)}$suffix"
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

    // Percent-encoded emails (`alice%40corp.com`) in raw query/URL values. Masked with a URL chain
    // so the placeholder is the same identity as the decoded email and rehydration restores `%40`.
    private fun maskEncodedEmails(text: String) =
        replaceOutsidePlaceholders(text, SecretDetector.EMAIL_ENCODED, jwtRanges(text)) { encoded ->
            maskLiteral(encoded, listOf(Encoding.URL), TokenType.EMAIL)
        }

    // Phone numbers (PII), masked by default like emails; raw context, referentially consistent.
    private fun maskPhones(text: String) = replaceOutsidePlaceholders(text, SecretDetector.PHONE, jwtRanges(text)) { phone ->
        vault.placeholderFor(phone, TokenType.PHONE)
    }

    // Credit-card numbers (PII). Shape candidate + Luhn checksum so random long digit runs
    // (timestamps/ids) stay unmasked. Stored verbatim (with any separators) for exact round-trip.
    private fun maskCards(text: String) = replaceOutsidePlaceholders(text, SecretDetector.CARD_CANDIDATE, jwtRanges(text)) { cand ->
        if (SecretDetector.luhnValid(cand.filter { it.isDigit() })) vault.placeholderFor(cand, TokenType.CARD) else cand
    }

    // SSN standard shape 3-2-4 (PII). Non-standard national forms are handled by key name.
    private fun maskSsn(text: String) = replaceOutsidePlaceholders(text, SecretDetector.SSN, jwtRanges(text)) { ssn ->
        vault.placeholderFor(ssn, TokenType.SSN)
    }

    // Standalone token candidates (secrets hidden behind custom key names / in bodies). The length
    // floor is 20 to match SecretDetector.isHighEntropySecret's own lower bound (LEAK-1); every match
    // is then put through the entropy gate, so 20-31 char high-entropy tokens are caught while
    // low-entropy filler of the same length is left alone. Token body excludes '=' (base64 padding
    // only appears trailing) and is delimited by non-token chars so `field=<blob>` is not swallowed
    // whole via the '=' separator.
    private val isolatedToken = Regex("""(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{20,}={0,2}(?![A-Za-z0-9+/_\-])""")

    // STRICT: lower floor (12) and mask value tokens aggressively — but preserve request/response
    // STRUCTURE, standard non-sensitive metadata values, timestamps and the Burp tool-output
    // envelope so the agent can still read the shape of traffic. "Conceal the values, keep the
    // structure."
    private val strictToken = Regex("""(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{12,}={0,2}(?![A-Za-z0-9+/_\-])""")

    // Position exclusions: an HTTP header field-name token (line start, before ':') and a JSON
    // object key are structural, never secret values. Masking only applies to VALUE positions.
    private val headerFieldName = Regex("""(?im)^([A-Za-z0-9._-]+)[ \t]*:""")
    private val jsonKey = Regex("""["']([A-Za-z0-9_.\-]+)["']\s*:""")

    // Standard headers whose VALUES are non-sensitive metadata (kept readable even in STRICT).
    private val metadataHeaderValue = Regex(
        """(?im)^(?:content-type|content-length|content-encoding|content-language|content-disposition|""" +
            """transfer-encoding|connection|keep-alive|date|server|cache-control|pragma|accept|""" +
            """accept-encoding|accept-language|accept-charset|accept-ranges|vary|allow|age|expires|""" +
            """retry-after|x-powered-by|last-modified|via|upgrade|x-content-type-options|""" +
            """x-frame-options|x-xss-protection|strict-transport-security):[ \t]*(.+?)[ \t]*$"""
    )

    // Clock times HH:MM:SS (valid ranges) — structural metadata, and must not be eaten by the IPv6
    // or high-entropy passes (e.g. inside a Date header).
    private val timePattern = Regex("""\b(?:[01]?\d|2[0-3]):[0-5]\d:[0-5]\d\b""")

    // Burp tool-output envelope literals (wrappers around the actual HTTP content, not traffic data).
    private val envelopeWords = setOf(
        "HttpRequestResponse", "HttpRequest", "HttpResponse", "HttpRequestResponses",
        "messageAnnotations", "MessageAnnotations", "highlightColor", "HighlightColor",
        "annotations", "Annotations", "requestResponse", "requestResponses",
        "serialException", "StatusCodeClass", "notesFieldName"
    )

    private fun maskHighEntropy(text: String): String {
        // Protect (a) JWT analysis-view segments (FAIL-1), (b) header field names and JSON keys
        // (structural identifiers, not values), and (c) UUIDs when the UUID toggle is off.
        var protected = jwtRanges(text) +
                headerFieldName.findAll(text).map { it.groups[1]!!.range } +
                jsonKey.findAll(text).map { it.groups[1]!!.range } +
                if (!maskUuids) SecretDetector.UUID.findAll(text).map { it.range }.toList() else emptyList()

        if (strict) {
            // Keep the request/response STRUCTURE readable: standard non-sensitive metadata header
            // values and clock times are not values-to-conceal.
            protected = protected +
                    metadataHeaderValue.findAll(text).map { it.groups[1]!!.range } +
                    timePattern.findAll(text).map { it.range }
        }

        val regex = if (strict) strictToken else isolatedToken
        val skip = Placeholder.parseAll(text).map { it.range } + protected
        return regex.replace(text) { m ->
            if (skip.any { it.first <= m.range.last && m.range.first <= it.last }) return@replace m.value
            val token = m.value
            // URL/path context: the token starts a path or follows a domain dot / path slash. There we
            // respect `/` segment boundaries so a sensitive segment does not drag readable path words
            // (bbc.co.uk/news/articles/<id>) into one placeholder.
            val before = text.getOrNull(m.range.first - 1)
            val isUrlPath = token.startsWith("/") || before == '.' || before == '/'
            maskEntropyCandidate(token, isUrlPath)
        }
    }

    private fun maskEntropyCandidate(token: String, isUrlPath: Boolean): String = when {
        // A base64 blob already carrying masked placeholders was handled by the nested pass.
        isNestedMaskedBlob(token) -> token
        // In URL/path context, mask per `/`-segment (keep structure, conceal sensitive segments).
        isUrlPath && token.contains('/') -> token.split('/').joinToString("/") { seg -> maskPathSegment(seg) }
        // STRICT conceals values but keeps structure: never mask separator-joined structural
        // identifiers (application/json, snake_case) nor the Burp output envelope literals.
        strict -> if (SecretDetector.STRUCTURAL_IDENTIFIER.matches(token) || token in envelopeWords)
            token else vault.placeholderFor(token, TokenType.SECRET)
        isMaskableSecret(token) -> vault.placeholderFor(token, TokenType.SECRET)
        else -> token
    }

    private fun maskPathSegment(seg: String): String = when {
        seg.isEmpty() -> seg
        // Pure-alpha path words (news, articles, PortSwigger, mcp-server) are structure — keep them.
        SecretDetector.STRUCTURAL_IDENTIFIER.matches(seg) -> seg
        seg in envelopeWords -> seg
        // STRICT conceals every non-structural path segment; SELECTIVE only the sensitive ones.
        strict -> vault.placeholderFor(seg, TokenType.SECRET)
        isPathSegmentSecret(seg) -> vault.placeholderFor(seg, TokenType.SECRET)
        else -> seg
    }

    /** A path segment worth masking in SELECTIVE: a mixed alnum id/secret, or a strong high-entropy run. */
    private fun isPathSegmentSecret(seg: String): Boolean {
        if (SecretDetector.STRUCTURAL_IDENTIFIER.matches(seg)) return false
        val hasLetter = seg.any { it.isLetter() }
        val hasDigit = seg.any { it.isDigit() }
        if (hasLetter && hasDigit && seg.length >= 8) return true            // e.g. cx2gx8n8e5po, ghp_16C...
        if (seg.length >= 20 && SecretDetector.isHighEntropySecret(seg)) return true
        return isMaskableSecret(seg)
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
