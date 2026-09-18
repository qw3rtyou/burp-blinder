package net.portswigger.mcp.blinder

/**
 * Placeholder grammar shared by the Masker (emit) and Rehydrator (parse):
 *
 *   {{TYPE_ID}}            static vault reference, raw context      e.g. {{COOKIE_SESSION_1}}
 *   {{TYPE_ID|chain}}      static vault reference with encoding     e.g. {{BASIC_1|b64}}, {{DATA_1|b64,u}}
 *   {{KIND:selector}}      managed dynamic token (CSRF/nonce)       e.g. {{CSRF:auto}}, {{CSRF:login}}
 *   {{KIND:selector|chain}} managed dynamic token with encoding     e.g. {{CSRF:auto|u}}
 *
 * The encoding chain is per-occurrence (never stored in the vault) so the agent can move a
 * placeholder into a new encoding context and rehydration still reproduces the correct bytes.
 */
object Placeholder {
    // head = TYPE_ID or KIND ; selector optional ; enc chain optional.
    val REGEX = Regex("""\{\{([A-Za-z0-9_]+)(?::([A-Za-z0-9_.\-]+))?(?:\|([a-z0-9,]+))?}}""")

    const val MANAGED_CSRF = "CSRF"
    const val MANAGED_NONCE = "NONCE"

    fun isManagedKind(head: String): Boolean = head == MANAGED_CSRF || head == MANAGED_NONCE

    data class Ref(
        val whole: String,
        val head: String,
        val selector: String?,
        val chain: List<Encoding>,
        val range: IntRange
    ) {
        val isManaged: Boolean get() = selector != null && isManagedKind(head)
        /** Base placeholder as stored in the vault (no selector, no chain). */
        val base: String get() = "{{$head}}"
    }

    fun parseAll(text: String): List<Ref> = REGEX.findAll(text).map { m ->
        Ref(
            whole = m.value,
            head = m.groupValues[1],
            selector = m.groupValues[2].ifEmpty { null },
            chain = Encoding.parseChain(m.groupValues.getOrNull(3)),
            range = m.range
        )
    }.toList()

    fun containsAny(text: String): Boolean = REGEX.containsMatchIn(text)

    /** Build the emitted placeholder for a base and an encoding chain (raw -> no suffix). */
    fun emit(base: String, chain: List<Encoding>): String {
        if (chain.isEmpty()) return base
        val inner = base.removePrefix("{{").removeSuffix("}}")
        return "{{$inner|${Encoding.chainTag(chain)}}}"
    }
}
