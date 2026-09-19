package net.portswigger.mcp.blinder

/**
 * Human-gate for the `reveal_placeholder` tool. Revealing a real secret to the agent is a
 * deliberate exception to the gateway's confidentiality contract, so it is ALWAYS mediated by a
 * human decision. The approver is injected: the Montoya glue shows a modal Burp dialog; headless
 * environments (and unit tests) use a stub. The top invariant is: no value is disclosed without an
 * explicit ALLOW decision from the human.
 */
enum class RevealDecision { ALLOW_ONCE, ALLOW_ALWAYS, DENY }

interface RevealApprover {
    /**
     * Blocking prompt. Implementations must NOT show the real value before the human approves —
     * only the placeholder token, a coarse type label and the value length. Returns the human's
     * decision, or [RevealDecision.DENY] on timeout / unavailable UI.
     */
    fun requestReveal(placeholder: String, typeLabel: String, valueLength: Int): RevealDecision
}

/** Fail-closed default: used headless / before a real approver is installed. */
object DenyingRevealApprover : RevealApprover {
    override fun requestReveal(placeholder: String, typeLabel: String, valueLength: Int): RevealDecision =
        RevealDecision.DENY
}
