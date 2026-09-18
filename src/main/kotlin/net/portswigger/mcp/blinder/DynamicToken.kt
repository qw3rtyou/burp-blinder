package net.portswigger.mcp.blinder

/**
 * Live store of dynamic tokens (CSRF, anti-forgery, nonce) captured from server responses. These
 * are NOT vault constants: the server mints a fresh one each time, so the gateway keeps the latest
 * value keyed by a logical name and injects it at send time via a managed placeholder such as
 * `{{CSRF:auto}}`. The agent never needs to see the value.
 */
class DynamicTokenStore {
    private val csrf = LinkedHashMap<String, String>()
    private val nonce = LinkedHashMap<String, String>()
    private val lock = Any()

    fun putCsrf(name: String, value: String) = synchronized(lock) { csrf[name] = value }
    fun putNonce(name: String, value: String) = synchronized(lock) { nonce[name] = value }

    /** `auto` returns the most recently captured token; a name returns that named token. */
    fun csrf(selector: String): String? = synchronized(lock) {
        if (selector == "auto") csrf.values.lastOrNull() else csrf[selector]
    }

    fun nonce(selector: String): String? = synchronized(lock) {
        if (selector == "auto") nonce.values.lastOrNull() else nonce[selector]
    }

    fun clear() = synchronized(lock) { csrf.clear(); nonce.clear() }
}

/**
 * Extraction rules for dynamic tokens. v1 ships general rules plus a hook list callers can extend
 * once real traffic is available (site-specific tuning). Extraction is name-pattern + location:
 * HTML hidden inputs, meta tags, Set-Cookie, and JSON response fields.
 */
class DynamicTokenExtractor(
    private val store: DynamicTokenStore,
    extraRules: List<Rule> = emptyList()
) {
    /** A tuning hook: given a response body/headers, produce (name, value) pairs. */
    fun interface Rule {
        fun extract(response: String): List<Pair<String, String>>
    }

    private val csrfNameHint = Regex("""csrf|xsrf|authenticity_token|anti.?forgery|__requestverificationtoken""", RegexOption.IGNORE_CASE)

    private val hiddenInput = Regex(
        """<input[^>]*type=["']hidden["'][^>]*>""", RegexOption.IGNORE_CASE
    )
    private val attrName = Regex("""name=["']([^"']+)["']""", RegexOption.IGNORE_CASE)
    private val attrValue = Regex("""value=["']([^"']*)["']""", RegexOption.IGNORE_CASE)

    private val metaTag = Regex(
        """<meta[^>]*name=["']([^"']*(?:csrf|xsrf)[^"']*)["'][^>]*content=["']([^"']*)["']""",
        RegexOption.IGNORE_CASE
    )
    private val setCookie = Regex("""(?im)^set-cookie:\s*([^=]+)=([^;\r\n]+)""")
    private val jsonField = Regex(
        """["']([A-Za-z0-9_]*(?:csrf|xsrf|token|nonce)[A-Za-z0-9_]*)["']\s*:\s*["']([^"']+)["']""",
        RegexOption.IGNORE_CASE
    )

    private val rules = extraRules

    /** Observe a full response (headers + body). Returns names captured (for logging). */
    fun observe(response: String): List<String> {
        val captured = mutableListOf<String>()

        for (m in hiddenInput.findAll(response)) {
            val tag = m.value
            val name = attrName.find(tag)?.groupValues?.get(1) ?: continue
            val value = attrValue.find(tag)?.groupValues?.get(1) ?: continue
            if (csrfNameHint.containsMatchIn(name) && value.isNotBlank()) {
                store.putCsrf(name, value); captured += name
            }
        }

        for (m in metaTag.findAll(response)) {
            val name = m.groupValues[1]
            val value = m.groupValues[2]
            if (value.isNotBlank()) { store.putCsrf(name, value); captured += name }
        }

        for (m in setCookie.findAll(response)) {
            val name = m.groupValues[1].trim()
            val value = m.groupValues[2].trim()
            if (csrfNameHint.containsMatchIn(name) && value.isNotBlank()) {
                store.putCsrf(name, value); captured += name
            }
        }

        for (m in jsonField.findAll(response)) {
            val name = m.groupValues[1]
            val value = m.groupValues[2]
            if (csrfNameHint.containsMatchIn(name) && value.isNotBlank()) {
                store.putCsrf(name, value); captured += name
            }
        }

        for (rule in rules) {
            for ((name, value) in rule.extract(response)) {
                store.putCsrf(name, value); captured += name
            }
        }

        return captured
    }
}
