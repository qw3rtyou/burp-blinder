package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * STRICT refinement (#17): "conceal the values, keep the structure". STRICT must mask all data
 * values (cookies/auth/IP/UUID/MAC/high-entropy) while leaving request/response structure, standard
 * metadata, timestamps and the Burp tool-output envelope readable.
 */
class StrictStructureTest {

    private val strict = Masker(Vault(), mode = MaskingMode.STRICT)

    private val sample = "HTTP/1.1 200 OK\r\n" +
        "Content-Type: application/json; charset=utf-8\r\n" +
        "Server: nginx/1.18.0\r\n" +
        "Date: Mon, 15 Jan 2024 10:30:45 GMT\r\n" +
        "Cache-Control: no-cache, private\r\n" +
        "Set-Cookie: sid=SESSIONabc123def456; Path=/\r\n" +
        "X-Real-IP: 203.0.113.45\r\n" +
        "\r\n" +
        "HttpRequestResponse{request=..., messageAnnotations=Annotations{highlightColor=NONE}}\r\n" +
        """{"request_id":"550e8400-e29b-41d4-a716-446655440000","secret":"abcdefghijklmnop","mac":"00:1A:2B:3C:4D:5E"}"""

    @Test
    fun `strict preserves structure and standard metadata`() {
        val out = strict.mask(sample)
        // Status line + header names.
        assertTrue(out.contains("HTTP/1.1 200 OK"), out)
        assertTrue(out.contains("Content-Type:"), out)
        assertTrue(out.contains("X-Real-IP:"), out)
        // Standard metadata VALUES.
        assertTrue(out.contains("application/json; charset=utf-8"), out)
        assertTrue(out.contains("nginx/1.18.0"), out)
        assertTrue(out.contains("no-cache, private"), out)
        // Date time is not eaten by IP/entropy passes.
        assertTrue(out.contains("10:30:45"), out)
        assertTrue(out.contains("15 Jan 2024"), out)
        // JSON keys.
        assertTrue(out.contains("\"request_id\":"), out)
        assertTrue(out.contains("\"secret\":"), out)
        // Tool-output envelope.
        assertTrue(out.contains("HttpRequestResponse{"), out)
        assertTrue(out.contains("messageAnnotations="), out)
        assertTrue(out.contains("highlightColor="), out)
    }

    @Test
    fun `strict masks all data values`() {
        val out = strict.mask(sample)
        assertFalse(out.contains("SESSIONabc123def456"), out)   // cookie value
        assertFalse(out.contains("203.0.113.45"), out)          // IP
        assertFalse(out.contains("550e8400-e29b-41d4-a716-446655440000"), out) // UUID
        assertFalse(out.contains("00:1A:2B:3C:4D:5E"), out)     // MAC
        assertFalse(out.contains("abcdefghijklmnop"), out)      // secret value
        assertTrue(out.contains("{{COOKIE_SESSION_1}}"), out)
        assertTrue(out.contains("{{IP_1}}"), out)
        assertTrue(out.contains("{{UUID_1}}"), out)
        assertTrue(out.contains("{{MAC_1}}"), out)
    }

    @Test
    fun `strict round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault, mode = MaskingMode.STRICT)
        val rehydrator = Rehydrator(vault)
        assertEquals(sample, rehydrator.rehydrate(masker.mask(sample)).text)
    }

    @Test
    fun `strict does not mask clock times as IPs`() {
        val out = Masker(Vault(), mode = MaskingMode.STRICT).mask("Started at 23:59:59 today")
        assertTrue(out.contains("23:59:59"), out)
        assertFalse(out.contains("{{IP"), out)
    }
}
