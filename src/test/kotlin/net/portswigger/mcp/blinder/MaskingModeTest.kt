package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MaskingModeTest {

    // ---- OFF ----
    @Test
    fun `OFF passes read output through unmasked`() {
        val gw = Gateway(maskingMode = MaskingMode.OFF)
        val raw = "Set-Cookie: sid=REAL-SESSION-VALUE-0001; Path=/"
        assertEquals(raw, gw.maskOutput("get_proxy_http_history", raw))
    }

    @Test
    fun `OFF does not rehydrate send input`() {
        val gw = Gateway(maskingMode = MaskingMode.OFF)
        gw.vault.placeholderFor("realvalue", TokenType.SECRET)
        val outcome = gw.rehydrateInput("send_http1_request", "x={{SECRET_1}}")
        assertEquals("x={{SECRET_1}}", outcome.text)
        assertFalse(outcome.signatureSkipped)
    }

    @Test
    fun `OFF still enforces deny-by-default tool policy`() {
        val gw = Gateway(maskingMode = MaskingMode.OFF)
        assertFalse(gw.isAllowed("some_unregistered_tool"))
        assertTrue(gw.isAllowed("get_proxy_http_history"))
    }

    // ---- SELECTIVE ----
    @Test
    fun `SELECTIVE masks detected secrets (default behaviour)`() {
        val gw = Gateway(maskingMode = MaskingMode.SELECTIVE)
        val out = gw.maskOutput("get_proxy_http_history", "Set-Cookie: sid=REAL-SESSION-VALUE-0001")
        assertFalse(out.contains("REAL-SESSION-VALUE-0001"), out)
        assertTrue(out.contains("{{COOKIE_SESSION_1}}"), out)
    }

    // ---- STRICT ----
    @Test
    fun `STRICT masks IP and UUID ignoring their toggles`() {
        val masker = Masker(Vault(), maskIpAddresses = false, maskUuids = false, mode = MaskingMode.STRICT)
        val out = masker.mask("""{"ip":"203.0.113.45","req":"550e8400-e29b-41d4-a716-446655440000"}""")
        assertFalse(out.contains("203.0.113.45"), out)
        assertFalse(out.contains("550e8400-e29b-41d4-a716-446655440000"), out)
        assertTrue(out.contains("{{IP_1}}"), out)
        assertTrue(out.contains("{{UUID_1}}"), out)
    }

    @Test
    fun `STRICT masks MAC addresses`() {
        val out = Masker(Vault(), mode = MaskingMode.STRICT).mask("device 00:1A:2B:3C:4D:5E online")
        assertFalse(out.contains("00:1A:2B:3C:4D:5E"), out)
        assertTrue(out.contains("{{MAC_1}}"), out)
    }

    @Test
    fun `STRICT masks low-shape tokens that SELECTIVE leaves readable`() {
        val value = "abcdefghijkl" // 12 chars, low entropy — below SELECTIVE's 20-floor
        val selective = Masker(Vault(), mode = MaskingMode.SELECTIVE).mask("""{"custom":"$value"}""")
        assertTrue(selective.contains(value), "SELECTIVE should leave low-shape readable: $selective")

        val strict = Masker(Vault(), mode = MaskingMode.STRICT).mask("""{"custom":"$value"}""")
        assertFalse(strict.contains(value), "STRICT should mask low-shape: $strict")
        assertTrue(strict.contains("{{SECRET_1}}"), strict)
    }

    @Test
    fun `STRICT masks every cookie value regardless of name`() {
        val out = Masker(Vault(), mode = MaskingMode.STRICT).mask("Cookie: theme=lightmode; sid=abc")
        assertFalse(out.contains("theme=lightmode"), out)
        assertTrue(out.contains("theme={{"), out)
    }

    @Test
    fun `STRICT round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault, mode = MaskingMode.STRICT)
        val rehydrator = Rehydrator(vault)
        val real = "GET / HTTP/1.1\r\nCookie: sid=SESSIONabc123\r\nX-Real-IP: 203.0.113.45\r\n\r\n"
        val masked = masker.mask(real)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
