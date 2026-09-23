package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-13: recon-usability for JS/asset contexts (SELECTIVE). (1) static asset filenames preserved,
 * (2) JS/CSS body skips heuristics but keeps strong hardcoded-secret shapes, (3) MIME tokens
 * preserved. STRICT stays aggressive; PII/keys in JSON/headers unaffected.
 */
class JsAssetPolicyTest {

    private fun sel(text: String) = Masker(Vault(), mode = MaskingMode.SELECTIVE).mask(text)

    private val jsResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n" +
        "Set-Cookie: sid=SESSIONabc123def456\r\n\r\n" +
        "var e={internal:1};var t=\"a1b2c3d4e5f6g7h8i9j0k1l2\";var n=1234567890123456;" +
        "var k=\"sk_live_abcdef0123456789ABCDEF\";var g=\"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\";" +
        "var db=\"postgres://u:p4ssw0rd@h/db\";var m=\"dev@corp.com\";"

    @Test
    fun `part1 static asset filename preserved`() {
        val out = sel("""<script src="/assets/index-a1b2c3D4.js"></script><link href="/assets/main-Xy9Z.css">""")
        assertTrue(out.contains("/assets/index-a1b2c3D4.js"), out)
        assertTrue(out.contains("/assets/main-Xy9Z.css"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    @Test
    fun `part2 js body skips heuristics but keeps strong secrets`() {
        val out = sel(jsResponse)
        // Header still masked (full pipeline on prelude).
        assertTrue(out.contains("sid={{COOKIE_SESSION_1}}"), out)
        // Heuristics skipped in JS body.
        assertTrue(out.contains("{internal:1}"), out)                 // IHOST suffix not masked
        assertTrue(out.contains("a1b2c3d4e5f6g7h8i9j0k1l2"), out)     // random minified token kept
        assertTrue(out.contains("1234567890123456"), out)            // non-Luhn minified number kept
        // Strong hardcoded secrets still masked.
        assertFalse(out.contains("sk_live_abcdef0123456789ABCDEF"), out)
        assertFalse(out.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"), out)
        assertFalse(out.contains("p4ssw0rd"), out)                    // connection-string password
        assertFalse(out.contains("dev@corp.com"), out)               // email kept masked
        assertTrue(out.contains("postgres://u:{{SECRET") , out)
    }

    @Test
    fun `part2 jwt in js body is selectively masked`() {
        val jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.SIG"
        val out = sel("HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\nvar t=\"$jwt\";")
        assertFalse(out.contains(".SIG\""), out)
        assertTrue(out.contains(".SIGNATURE_MASKED"), out)
    }

    @Test
    fun `part3 mime token preserved`() {
        val out = sel("Accept: application/xhtml+xml,text/html,application/vnd.api+json")
        assertTrue(out.contains("application/xhtml+xml"), out)
        assertTrue(out.contains("application/vnd.api+json"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    @Test
    fun `regression json body still masks pii and keys`() {
        val out = sel("""{"cardNumber":"4111 1111 1111 1111","phone":"1-770-736-8031","email":"x@y.com","DB_PASSWORD":"pw"}""")
        assertFalse(out.contains("4111 1111 1111 1111"), out)
        assertFalse(out.contains("1-770-736-8031"), out)
        assertFalse(out.contains("x@y.com"), out)
        assertFalse(out.contains("\"pw\""), out)
    }

    @Test
    fun `strict keeps aggressive masking in js`() {
        val out = Masker(Vault(), mode = MaskingMode.STRICT).mask(jsResponse)
        assertFalse(out.contains("a1b2c3d4e5f6g7h8i9j0k1l2"), out) // STRICT masks minified token
        assertFalse(out.contains("1234567890123456"), out)         // STRICT masks number
    }

    @Test
    fun `js body strong-secret masking round-trips (no jwt)`() {
        val vault = Vault()
        val masker = Masker(vault, mode = MaskingMode.SELECTIVE)
        val rehydrator = Rehydrator(vault)
        val real = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" +
            "var k=\"sk_live_abcdef0123456789ABCDEF\";var db=\"postgres://u:p4ssw0rd@h/db\";var m=\"dev@corp.com\";"
        val masked = masker.mask(real)
        assertFalse(masked.contains("sk_live_abcdef0123456789ABCDEF"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
