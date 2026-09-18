package net.portswigger.mcp.blinder

/**
 * Egress-side rehydration. Replaces placeholders the agent wrote with the real values from the
 * vault (static secrets) or the live dynamic-token store (CSRF/nonce), applying each occurrence's
 * encoding chain so the bytes that reach the target are correct.
 *
 * Symmetry with the Masker gives round-trip identity: real request -> mask -> (agent edits) ->
 * rehydrate reproduces the exact original bytes for the untouched parts.
 */
class Rehydrator(
    private val vault: Vault,
    private val dynamicTokens: DynamicTokenStore = DynamicTokenStore()
) {
    data class Result(
        val text: String,
        /** Placeholders that could not be resolved (unknown vault ref or missing dynamic token). */
        val residual: List<String>
    ) {
        val hasResidual: Boolean get() = residual.isNotEmpty()
    }

    fun rehydrate(input: String): Result {
        val afterNested = rehydrateNestedBase64(input)
        val residual = mutableListOf<String>()
        val out = rehydratePlaceholders(afterNested, residual)
        return Result(out, residual)
    }

    /** Convenience for call sites that just want the resulting string. */
    fun rehydrateText(input: String): String = rehydrate(input).text

    private fun rehydratePlaceholders(text: String, residual: MutableList<String>): String {
        return Placeholder.REGEX.replace(text) { m ->
            val ref = Placeholder.parseAll(m.value).firstOrNull()
                ?: return@replace m.value
            val real = resolve(ref)
            if (real == null) {
                residual += m.value
                m.value
            } else {
                ref.chain.applyEncode(real)
            }
        }
    }

    private fun resolve(ref: Placeholder.Ref): String? = when {
        ref.isManaged && ref.head == Placeholder.MANAGED_CSRF -> dynamicTokens.csrf(ref.selector!!)
        ref.isManaged && ref.head == Placeholder.MANAGED_NONCE -> dynamicTokens.nonce(ref.selector!!)
        else -> vault.realFor(ref.base)
    }

    // Reverse of Masker.maskNestedBase64: a base64 blob whose decoded content carries placeholders.
    private val base64Blob = Regex("""[A-Za-z0-9+/]{16,}={0,2}""")
    private fun rehydrateNestedBase64(text: String): String = base64Blob.replace(text) { m ->
        val literal = m.value
        val decoded = runCatching { Encoding.BASE64.decode(literal) }.getOrNull()
            ?: return@replace literal
        if (!Placeholder.containsAny(decoded)) return@replace literal
        if (Encoding.BASE64.encode(decoded) != literal) return@replace literal
        val rehydratedInner = rehydrate(decoded).text
        Encoding.BASE64.encode(rehydratedInner)
    }
}
