package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-6 leak fix: key-based masking for form-urlencoded bodies (and query strings). Login POSTs
 * are almost always form-urlencoded, so an unmasked `password=` in proxy history leaks credentials.
 */
class FormKeyMaskingTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `sensitive form body keys are masked, non-sensitive kept`() {
        val body = "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
                "password=P@ssw0rd-secret123&username=admin&scope=read&api_key=AKIAZK7Q4XR9PLMN2WYB"
        val out = mask(body)
        assertFalse(out.contains("P@ssw0rd-secret123"), out)
        assertFalse(out.contains("AKIAZK7Q4XR9PLMN2WYB"), out)
        assertTrue(out.contains("password={{SECRET_1}}"), out)
        assertTrue(out.contains("api_key={{SECRET_2}}"), out)
        // Non-sensitive keys survive.
        assertTrue(out.contains("username=admin"), out)
        assertTrue(out.contains("scope=read"), out)
    }

    @Test
    fun `sensitive query keys are masked, non-sensitive kept`() {
        val out = mask("GET /s?password=hunter2&q=cats&access_token=abcdef123456 HTTP/1.1\r\nHost: x\r\n\r\n")
        assertFalse(out.contains("hunter2"), out)
        assertFalse(out.contains("abcdef123456"), out)
        assertTrue(out.contains("q=cats"), out)
        assertTrue(out.contains("password={{SECRET_1|u}}"), out)
    }

    @Test
    fun `token suffix keys masked, similar non-sensitive keys untouched`() {
        val out = mask("POST /b HTTP/1.1\r\n\r\ncsrf_token=abc123def456&continuation=xyz789&username=bob")
        assertFalse(out.contains("abc123def456"), out)
        assertTrue(out.contains("csrf_token={{SECRET_1}}"), out)
        assertTrue(out.contains("continuation=xyz789"), out)
        assertTrue(out.contains("username=bob"), out)
    }

    @Test
    fun `form and query masking round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
                "password=P@ssw0rd-secret123&username=admin"
        val masked = masker.mask(real)
        assertFalse(masked.contains("P@ssw0rd-secret123"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `regression - non-form key=value in headers is not over-masked`() {
        val out = mask("GET / HTTP/1.1\r\nCache-Control: max-age=0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n")
        assertTrue(out.contains("max-age=0"), out)
        assertTrue(out.contains("charset=utf-8"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }
}
