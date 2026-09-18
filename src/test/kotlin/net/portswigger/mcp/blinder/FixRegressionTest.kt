package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.Base64

/** LEAK-1: 20-31 char high-entropy secrets behind custom key names must be masked. */
class Leak1HighEntropyWindowTest {

    private fun masker() = Vault().let { it to Masker(it) }

    private val entropic24 = "aZ9qP2xL7mK3nB6vC1wR8tY4" // 24 chars, high entropy

    @Test
    fun `24-char high-entropy value behind a custom cookie name is masked (P2)`() {
        val (_, masker) = masker()
        val out = masker.mask("Cookie: myapptok=$entropic24; theme=dark")
        assertFalse(out.contains(entropic24), "leaked: $out")
        assertTrue(out.contains("{{SECRET_1}}"), out)
        assertTrue(out.contains("theme=dark"))
    }

    @Test
    fun `24-char high-entropy value behind a custom JSON key is masked (P2b)`() {
        val (_, masker) = masker()
        val out = masker.mask("""{"myfield":"$entropic24"}""")
        assertFalse(out.contains(entropic24), "leaked: $out")
        assertTrue(out.contains("{{SECRET_1}}"), out)
    }

    @Test
    fun `low-entropy filler of the same length is left alone (entropy gate suppresses over-masking)`() {
        val (_, masker) = masker()
        val filler = "aaaaaaaaaaaaaaaaaaaaaaaa" // 24 chars, entropy ~0
        val out = masker.mask("Cookie: myapptok=$filler; theme=dark")
        assertTrue(out.contains(filler), "low-entropy filler should not be masked: $out")
        assertFalse(out.contains("{{SECRET"), out)
    }
}

/** FAIL-2: a bare sig/signature field must not trigger a signature skip on a normal request. */
class Fail2SignatureNarrowingTest {

    private fun gateway() = Gateway()

    @Test
    fun `normal request with short sig field is rehydrated, not skipped (P8)`() {
        val gw = gateway()
        gw.vault.placeholderFor("SESSIONVAL-123", TokenType.COOKIE_SESSION) // {{COOKIE_SESSION_1}}
        val req = "POST /pay HTTP/1.1\r\n" +
                "Cookie: sessionId={{COOKIE_SESSION_1}}\r\n\r\n" +
                """{"sig":"abc","data":1}"""
        val outcome = gw.rehydrateInput("send_http1_request", req)
        assertFalse(outcome.signatureSkipped, "must not be treated as signed")
        assertTrue(outcome.text.contains("sessionId=SESSIONVAL-123"), outcome.text)
        assertTrue(outcome.residual.isEmpty())
    }

    @Test
    fun `query with short sig value is rehydrated, not skipped (P8b)`() {
        val gw = gateway()
        gw.vault.placeholderFor("SID9", TokenType.COOKIE_SESSION)
        val outcome = gw.rehydrateInput(
            "send_http1_request",
            "GET /x?sig=deadbeef&id={{COOKIE_SESSION_1}} HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        assertFalse(outcome.signatureSkipped)
        assertTrue(outcome.text.contains("id=SID9"), outcome.text)
    }

    @Test
    fun `real signature-shaped value is still skipped`() {
        val hexSig = "a".repeat(64) // 64 hex chars = real signature shape
        assertTrue(SignatureDetector.isSigned("POST /w HTTP/1.1\r\n\r\n{\"signature\":\"$hexSig\"}"))
        assertTrue(SignatureDetector.isSigned("POST /w HTTP/1.1\r\nX-Hub-Signature-256: sha256=abc\r\n\r\nbody"))
        assertTrue(SignatureDetector.isSigned("oauth_signature=\"abc\"&oauth_nonce=\"1\""))
    }

    @Test
    fun `bare short sig field is not signed`() {
        assertFalse(SignatureDetector.isSigned("POST /w HTTP/1.1\r\n\r\n{\"sig\":\"abc\",\"data\":1}"))
        assertFalse(SignatureDetector.isSigned("GET /x?sig=deadbeef HTTP/1.1\r\nHost: x\r\n\r\n"))
    }
}

/** FAIL-1: the FULL mask() path (not just JwtMasker unit) must preserve JWT structure. */
class Fail1JwtFullPathTest {

    private val urlEnc = Base64.getUrlEncoder().withoutPadding()
    private val urlDec = Base64.getUrlDecoder()
    private fun seg(json: String) = urlEnc.encodeToString(json.toByteArray(StandardCharsets.UTF_8))
    private fun buildJwt(h: String, p: String) = "${seg(h)}.${seg(p)}.FAKESIG0123456789ABCDEF"

    @Test
    fun `raw body JWT keeps alg, claim keys and structure through full mask (P1b)`() {
        val jwt = buildJwt(
            """{"alg":"none","typ":"JWT"}""",
            """{"sub":"1234567890","name":"John Doe","email":"john@example.com","admin":true}"""
        )
        val out = Masker(Vault()).mask("here is a token $jwt end")

        // Not clobbered into opaque {{SECRET}} placeholders.
        assertFalse(out.contains("{{SECRET"), "JWT was clobbered by high-entropy pass: $out")
        assertTrue(out.contains(".SIGNATURE_MASKED"), out)

        val parts = out.removePrefix("here is a token ").removeSuffix(" end").split(".")
        assertEquals(3, parts.size)
        val header = String(urlDec.decode(parts[0]), StandardCharsets.UTF_8)
        val payload = String(urlDec.decode(parts[1]), StandardCharsets.UTF_8)
        assertTrue(header.contains("\"alg\":\"none\""), header)
        assertTrue(payload.contains("\"sub\""))
        assertTrue(payload.contains("\"admin\":true"), payload)
        assertFalse(payload.contains("John Doe"))
        assertFalse(payload.contains("1234567890"))
    }

    @Test
    fun `JSON id_token JWT is selectively masked, not opaquely vaulted`() {
        val jwt = buildJwt("""{"alg":"HS256","typ":"JWT"}""", """{"sub":"u1","role":"admin"}""")
        val out = Masker(Vault()).mask("""{"id_token":"$jwt"}""")
        assertFalse(out.contains("{{JWT"), "id_token should not be opaquely vaulted: $out")
        assertTrue(out.contains(".SIGNATURE_MASKED"), out)
        assertTrue(out.contains("\"id_token\":\"eyJ"), out)
    }
}

/** LEAK-2 (policy toggle, default OFF): IP masking. */
class Leak2IpToggleTest {

    @Test
    fun `IPs pass through when toggle is OFF (default behaviour preserved)`() {
        val out = Masker(Vault(), maskIpAddresses = false).mask("""{"clientIp":"203.0.113.45"}""")
        assertTrue(out.contains("203.0.113.45"), out)
    }

    @Test
    fun `IPv4 is masked and round-trips when toggle is ON`() {
        val vault = Vault()
        val masker = Masker(vault, maskIpAddresses = true)
        val rehydrator = Rehydrator(vault)
        val real = """{"clientIp":"203.0.113.45"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("203.0.113.45"), masked)
        assertTrue(masked.contains("{{IP_1}}"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `IPv6 is masked and round-trips when toggle is ON`() {
        val vault = Vault()
        val masker = Masker(vault, maskIpAddresses = true)
        val rehydrator = Rehydrator(vault)
        val real = "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 connected"
        val masked = masker.mask(real)
        assertFalse(masked.contains("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), masked)
        assertTrue(masked.contains("{{IP_1}}"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `same IP maps to the same placeholder (referential consistency)`() {
        val out = Masker(Vault(), maskIpAddresses = true)
            .mask("a=10.0.0.1 b=10.0.0.1 c=10.0.0.2")
        assertEquals(2, Regex("\\{\\{IP_1}}").findAll(out).count(), out)
        assertTrue(out.contains("{{IP_2}}"), out)
    }
}
