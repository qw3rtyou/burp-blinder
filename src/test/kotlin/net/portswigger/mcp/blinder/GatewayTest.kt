package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class GatewayTest {

    @Test
    fun `read tool output is masked, neutral tool output is untouched`() {
        val gateway = Gateway()
        val raw = "Set-Cookie: JSESSIONID=REAL-SESSION-VALUE-001; Path=/"
        val maskedRead = gateway.maskOutput("get_proxy_http_history", raw)
        assertFalse(maskedRead.contains("REAL-SESSION-VALUE-001"))
        assertTrue(maskedRead.contains("{{COOKIE_SESSION_1}}"), maskedRead)

        // A neutral tool's output is passed through verbatim.
        assertEquals(raw, gateway.maskOutput("url_encode", raw))
    }

    @Test
    fun `end to end - agent sees placeholder from read then sends it back and it rehydrates`() {
        val gateway = Gateway()
        // 1. A read tool reveals a response; the vault learns the secret.
        val masked = gateway.maskOutput(
            "send_http1_request",
            "HTTP/1.1 200 OK\r\nSet-Cookie: sid=TOP-SECRET-SESSION-9animal; Path=/\r\n\r\n"
        )
        val placeholder = Regex("\\{\\{COOKIE_SESSION_\\d+}}").find(masked)?.value
        assertTrue(placeholder != null, "expected a session placeholder in $masked")

        // 2. The agent composes a new request using only the placeholder.
        val outcome = gateway.rehydrateInput(
            "send_http1_request",
            "GET /account HTTP/1.1\r\nHost: bank.example\r\nCookie: sid=$placeholder\r\n\r\n"
        )
        assertEquals(
            "GET /account HTTP/1.1\r\nHost: bank.example\r\nCookie: sid=TOP-SECRET-SESSION-9animal\r\n\r\n",
            outcome.text
        )
        assertFalse(outcome.signatureSkipped)
        assertTrue(outcome.residual.isEmpty())
    }

    @Test
    fun `deny-by-default - unknown tool is refused`() {
        val gateway = Gateway()
        assertFalse(gateway.isAllowed("newly_added_upstream_tool"))
        assertTrue(gateway.denyMessage.isNotBlank())
    }

    @Test
    fun `signed request is skipped, not corrupted`() {
        val gateway = Gateway()
        gateway.vault.placeholderFor("realvalue", TokenType.SECRET) // {{SECRET_1}}
        val signed = "POST /webhook HTTP/1.1\r\nX-Hub-Signature-256: sha256=deadbeef\r\n\r\nvalue={{SECRET_1}}"
        val outcome = gateway.rehydrateInput("send_http1_request", signed)
        assertTrue(outcome.signatureSkipped)
        assertEquals(signed, outcome.text, "signed request must be left untouched")
        assertTrue(outcome.text.contains("{{SECRET_1}}"))
    }

    @Test
    fun `clearSession empties the vault and dynamic tokens`() {
        val gateway = Gateway()
        gateway.maskOutput("get_proxy_http_history", "Authorization: Bearer SOME-BEARER-abc-123")
        gateway.captureResponse("""<input type="hidden" name="csrf_token" value="X-1">""")
        assertTrue(gateway.vault.size() > 0)
        gateway.clearSession()
        assertEquals(0, gateway.vault.size())
        assertEquals(null, gateway.dynamicTokens.csrf("auto"))
    }
}
