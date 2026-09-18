package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.Base64

class JwtMaskerTest {

    private val urlEnc = Base64.getUrlEncoder().withoutPadding()
    private val urlDec = Base64.getUrlDecoder()

    private fun seg(json: String) = urlEnc.encodeToString(json.toByteArray(StandardCharsets.UTF_8))

    private fun buildJwt(header: String, payload: String) = "${seg(header)}.${seg(payload)}.FAKESIGNATURE"

    @Test
    fun `structure and claim keys preserved, sensitive values masked`() {
        val header = """{"alg":"HS256","typ":"JWT"}"""
        val payload = """{"sub":"1234567890","name":"John Doe","email":"john@example.com","admin":true,"role":"user"}"""
        val jwt = buildJwt(header, payload)

        val masked = JwtMasker.selectiveMask(jwt)
        val parts = masked.split(".")
        assertEquals(3, parts.size)

        // Header (alg/typ) preserved verbatim.
        assertEquals(seg(header), parts[0])

        // Signature not carried through.
        assertEquals("SIGNATURE_MASKED", parts[2])

        val maskedPayload = String(urlDec.decode(parts[1]), StandardCharsets.UTF_8)

        // Claim KEYS preserved (structure/analysis value kept).
        assertTrue(maskedPayload.contains("\"sub\""))
        assertTrue(maskedPayload.contains("\"name\""))
        assertTrue(maskedPayload.contains("\"email\""))
        assertTrue(maskedPayload.contains("\"admin\""))
        assertTrue(maskedPayload.contains("\"role\""))

        // Non-sensitive claim values preserved.
        assertTrue(maskedPayload.contains("\"admin\":true"), maskedPayload)
        assertTrue(maskedPayload.contains("\"role\":\"user\""), maskedPayload)

        // Sensitive claim VALUES masked (real identity gone).
        assertFalse(maskedPayload.contains("John Doe"))
        assertFalse(maskedPayload.contains("john@example.com"))
        assertFalse(maskedPayload.contains("1234567890"))
        assertTrue(maskedPayload.contains("@blinded.invalid"), "email should stay email-shaped: $maskedPayload")
    }

    @Test
    fun `alg none is still visible for analysis`() {
        val jwt = buildJwt("""{"alg":"none","typ":"JWT"}""", """{"sub":"admin","email":"a@b.com"}""")
        val masked = JwtMasker.selectiveMask(jwt)
        val header = String(urlDec.decode(masked.split(".")[0]), StandardCharsets.UTF_8)
        assertTrue(header.contains("\"alg\":\"none\""), header)
    }

    @Test
    fun `non-jwt input is returned unchanged`() {
        assertEquals("not.a.jwt.token", JwtMasker.selectiveMask("not.a.jwt.token"))
        assertEquals("plain", JwtMasker.selectiveMask("plain"))
    }
}
