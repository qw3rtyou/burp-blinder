package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MaskerTest {

    private fun freshMasker(): Pair<Vault, Masker> {
        val vault = Vault()
        return vault to Masker(vault)
    }

    @Test
    fun `authorization bearer value is masked and the real token never appears`() {
        val (_, masker) = freshMasker()
        val token = "abcDEF1234567890abcDEF1234567890abcd"
        val out = masker.mask("Authorization: Bearer $token")
        assertFalse(out.contains(token), "raw token leaked: $out")
        assertTrue(out.startsWith("Authorization: Bearer {{BEARER_1}}"), out)
    }

    @Test
    fun `sensitive cookies are masked in Cookie and Set-Cookie`() {
        val (_, masker) = freshMasker()
        val out = masker.mask("Cookie: a=1; sessionId=TOPSECRET; theme=dark")
        assertFalse(out.contains("TOPSECRET"))
        assertTrue(out.contains("sessionId={{COOKIE_SESSION_1}}"), out)
        assertTrue(out.contains("a=1"))
        assertTrue(out.contains("theme=dark"))
    }

    @Test
    fun `same cookie value across two headers maps to the same placeholder`() {
        val (_, masker) = freshMasker()
        val out = masker.mask("Cookie: sid=SAMEVALUE\nSet-Cookie: sid=SAMEVALUE; Path=/")
        assertFalse(out.contains("SAMEVALUE"))
        // Referential consistency: both occurrences use COOKIE_SESSION_1.
        assertEquals(2, Regex("\\{\\{COOKIE_SESSION_1}}").findAll(out).count(), out)
    }

    @Test
    fun `api key header is masked`() {
        val (_, masker) = freshMasker()
        val out = masker.mask("X-API-Key: sk_live_0123456789abcdef0123")
        assertFalse(out.contains("sk_live_0123456789abcdef0123"))
        assertTrue(out.contains("X-API-Key: {{APIKEY_1}}"), out)
    }

    @Test
    fun `email in body is masked`() {
        val (_, masker) = freshMasker()
        val out = masker.mask("The user is john.doe@example.com today")
        assertFalse(out.contains("john.doe@example.com"))
        assertTrue(out.contains("{{EMAIL_1}}"), out)
    }

    @Test
    fun `PEM private key block is masked`() {
        val (_, masker) = freshMasker()
        val pem = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBg\nkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----"
        val out = masker.mask("key:\n$pem\nend")
        assertFalse(out.contains("MIIBVAIBADANBg"))
        assertTrue(out.contains("{{PEM_1}}"), out)
    }

    @Test
    fun `json sensitive value is masked with json context`() {
        val (_, masker) = freshMasker()
        val out = masker.mask("""{"user":"bob","access_token":"tok-abc-123"}""")
        assertFalse(out.contains("tok-abc-123"))
        assertTrue(out.contains("\"access_token\":\"{{BEARER_1|j}}\""), out)
        assertTrue(out.contains("\"user\":\"bob\""), "non-sensitive value should survive: $out")
    }

    @Test
    fun `high entropy standalone token in body is masked (bias to over-mask)`() {
        val (_, masker) = freshMasker()
        val secret = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        val out = masker.mask("apiSecret=$secret")
        assertFalse(out.contains(secret))
        assertTrue(out.contains("{{SECRET_1}}"), out)
    }

    @Test
    fun `raw HTTP request masks then rehydrates to identical bytes (round-trip)`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = "GET / HTTP/1.1\r\n" +
                "Host: victim.example\r\n" +
                "Authorization: Bearer eyToken-value-9animal\r\n" +
                "Cookie: sid=ABCDEF0011; theme=dark\r\n\r\n"
        val masked = masker.mask(real)
        assertFalse(masked.contains("eyToken-value-9animal"))
        assertFalse(masked.contains("ABCDEF0011"))
        val result = rehydrator.rehydrate(masked)
        assertEquals(real, result.text)
        assertFalse(result.hasResidual)
    }

    @Test
    fun `nested base64-of-json body masks inner secret and round-trips`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val innerJson = """{"session":"DEEPSECRET-inside-blob-0011"}"""
        val blob = Encoding.BASE64.encode(innerJson)
        val real = "payload=$blob"

        val masked = masker.mask(real)
        assertFalse(masked.contains("DEEPSECRET-inside-blob-0011"), "secret survived inside blob: $masked")
        assertFalse(masked.contains(blob), "blob should have been re-encoded after inner masking")

        val result = rehydrator.rehydrate(masked)
        assertEquals(real, result.text)
        assertFalse(result.hasResidual)
    }
}
