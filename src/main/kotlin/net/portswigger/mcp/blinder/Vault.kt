package net.portswigger.mcp.blinder

/**
 * Type hints embedded in placeholders. The hint helps the agent's analysis (it can tell a cookie
 * from a bearer token) while the numeric id guarantees referential consistency.
 */
enum class TokenType(val prefix: String) {
    COOKIE_SESSION("COOKIE_SESSION"),
    COOKIE("COOKIE"),
    BEARER("BEARER"),
    BASIC("BASIC"),
    APIKEY("APIKEY"),
    JWT("JWT"),
    EMAIL("EMAIL"),
    PEM("PEM"),
    IP("IP"),
    UUID("UUID"),
    PHONE("PHONE"),
    CARD("CARD"),
    SSN("SSN"),
    MAC("MAC"),
    IHOST("IHOST"),
    SECRET("SECRET");

    companion object {
        private val byPrefix = entries.associateBy { it.prefix }
        fun fromPrefix(prefix: String): TokenType? = byPrefix[prefix]
    }
}

/**
 * The secret vault. Holds the bidirectional mapping between real values and placeholders for the
 * life of a session. Lives only in Burp process memory and is never serialised onto the agent
 * channel.
 *
 * Referential consistency: the same real value always maps to the same placeholder, and different
 * values always map to different placeholders. This lets the agent reason about "same/different"
 * (IDOR, session comparison) without ever seeing the secret.
 *
 * Thread-safe: the MCP tool wrappers and the Montoya HttpHandler share a single instance and may
 * touch it concurrently.
 */
class Vault {
    private val realToPlaceholder = HashMap<String, String>()
    private val placeholderToReal = HashMap<String, String>()
    private val counters = HashMap<String, Int>()
    private val lock = Any()

    /** Base placeholder text, e.g. `{{COOKIE_SESSION_1}}` (no encoding suffix). */
    fun placeholderFor(realValue: String, type: TokenType): String = synchronized(lock) {
        realToPlaceholder[realValue]?.let { return it }
        val n = (counters[type.prefix] ?: 0) + 1
        counters[type.prefix] = n
        val placeholder = "{{${type.prefix}_$n}}"
        realToPlaceholder[realValue] = placeholder
        placeholderToReal[placeholder] = realValue
        placeholder
    }

    /** Look up the real value for a base placeholder, or null if unknown (deny-by-default). */
    fun realFor(basePlaceholder: String): String? = synchronized(lock) { placeholderToReal[basePlaceholder] }

    fun knows(realValue: String): Boolean = synchronized(lock) { realToPlaceholder.containsKey(realValue) }

    fun size(): Int = synchronized(lock) { placeholderToReal.size }

    /** Clear all secrets. Call on session/target teardown to minimise secret residency. */
    fun clear() = synchronized(lock) {
        realToPlaceholder.clear()
        placeholderToReal.clear()
        counters.clear()
    }
}
