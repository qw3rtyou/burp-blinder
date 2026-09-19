package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RevealTest {

    private class ScriptedApprover(private vararg val decisions: RevealDecision) : RevealApprover {
        var calls = 0
        override fun requestReveal(placeholder: String, typeLabel: String, valueLength: Int): RevealDecision {
            val d = decisions.getOrElse(calls) { RevealDecision.DENY }
            calls++
            return d
        }
    }

    private fun gatewayWithSecret(
        approver: RevealApprover,
        log: (String) -> Unit = {}
    ): Pair<Gateway, String> {
        val gw = Gateway(log = log, revealApprover = approver)
        // Populate the vault via a read tool so we have a real placeholder.
        val masked = gw.maskOutput("get_proxy_http_history", "Set-Cookie: sid=TOP-SECRET-SESSION-9animal")
        val placeholder = Regex("\\{\\{COOKIE_SESSION_\\d+}}").find(masked)!!.value
        return gw to placeholder
    }

    @Test
    fun `allow once returns the real value`() {
        val (gw, ph) = gatewayWithSecret(ScriptedApprover(RevealDecision.ALLOW_ONCE))
        assertEquals("TOP-SECRET-SESSION-9animal", gw.reveal(ph))
    }

    @Test
    fun `deny does not disclose the value`() {
        val (gw, ph) = gatewayWithSecret(ScriptedApprover(RevealDecision.DENY))
        val result = gw.reveal(ph)
        assertFalse(result.contains("TOP-SECRET-SESSION-9animal"), "value leaked on deny: $result")
        assertTrue(result.contains("denied", ignoreCase = true), result)
    }

    @Test
    fun `default approver is fail-closed (deny)`() {
        val gw = Gateway() // DenyingRevealApprover by default
        val masked = gw.maskOutput("get_proxy_http_history", "Set-Cookie: sid=SECRETVAL123")
        val ph = Regex("\\{\\{COOKIE_SESSION_\\d+}}").find(masked)!!.value
        val result = gw.reveal(ph)
        assertFalse(result.contains("SECRETVAL123"), result)
    }

    @Test
    fun `always allow adds to session allowlist and auto-approves next time`() {
        // First call ALLOW_ALWAYS, subsequent calls DENY — but the value is allowlisted so it stays revealed.
        val approver = ScriptedApprover(RevealDecision.ALLOW_ALWAYS, RevealDecision.DENY)
        val (gw, ph) = gatewayWithSecret(approver)
        assertEquals("TOP-SECRET-SESSION-9animal", gw.reveal(ph))
        assertEquals("TOP-SECRET-SESSION-9animal", gw.reveal(ph), "should be auto-approved from allowlist")
        assertEquals(1, approver.calls, "second reveal must not re-prompt the human")
    }

    @Test
    fun `unknown placeholder returns not-found without prompting`() {
        val approver = ScriptedApprover(RevealDecision.ALLOW_ONCE)
        val gw = Gateway(revealApprover = approver)
        val result = gw.reveal("{{COOKIE_SESSION_99}}")
        assertTrue(result.contains("unknown", ignoreCase = true), result)
        assertEquals(0, approver.calls)
    }

    @Test
    fun `reveal output is never masked and never rehydrated by policy`() {
        assertTrue(ToolPolicy.isAllowed("reveal_placeholder"))
        assertFalse(ToolPolicy.needsOutputMasking("reveal_placeholder"))
        assertFalse(ToolPolicy.needsInputRehydration("reveal_placeholder"))
        // maskOutput leaves reveal output verbatim (it is not in OUTPUT_MASK_TOOLS).
        val gw = Gateway()
        assertEquals("the-real-value", gw.maskOutput("reveal_placeholder", "the-real-value"))
    }

    @Test
    fun `every reveal decision is audit-logged`() {
        val logs = mutableListOf<String>()
        val (gw, ph) = gatewayWithSecret(ScriptedApprover(RevealDecision.ALLOW_ONCE)) { logs.add(it) }
        gw.reveal(ph)
        assertTrue(logs.any { it.contains("reveal-audit") && it.contains("ALLOW_ONCE") }, logs.toString())
    }
}
