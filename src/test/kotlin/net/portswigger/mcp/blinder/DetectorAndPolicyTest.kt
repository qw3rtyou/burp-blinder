package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SecretDetectorTest {

    @Test
    fun `jwt shape detected`() {
        assertTrue(SecretDetector.looksLikeJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123"))
        assertFalse(SecretDetector.looksLikeJwt("hello.world.now"))
    }

    @Test
    fun `high entropy secret heuristic`() {
        assertTrue(SecretDetector.isHighEntropySecret("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"))
        assertFalse(SecretDetector.isHighEntropySecret("short"))
        assertFalse(SecretDetector.isHighEntropySecret("the quick brown fox jumps"))
    }

    @Test
    fun `sensitive cookie and credential header names`() {
        assertTrue(SecretDetector.isSensitiveCookieName("JSESSIONID"))
        assertTrue(SecretDetector.isSensitiveCookieName("csrf_token"))
        assertFalse(SecretDetector.isSensitiveCookieName("theme"))
        assertTrue(SecretDetector.isCredentialHeader("Authorization"))
        assertTrue(SecretDetector.isCredentialHeader("x-api-key"))
        assertFalse(SecretDetector.isCredentialHeader("Accept"))
    }

    @Test
    fun `email shape detected`() {
        assertTrue(SecretDetector.EMAIL.containsMatchIn("reach me at a.b+c@sub.example.co"))
        assertFalse(SecretDetector.EMAIL.containsMatchIn("no email here"))
    }
}

class SignatureDetectorTest {

    @Test
    fun `signature header marks request as signed`() {
        assertTrue(SignatureDetector.isSigned("POST /x HTTP/1.1\r\nX-Hub-Signature-256: sha256=abc\r\n\r\nbody"))
        assertTrue(SignatureDetector.isSigned("GET / HTTP/1.1\r\nSignature: keyId=\"k\",signature=\"s\"\r\n\r\n"))
    }

    @Test
    fun `aws sigv4 and oauth markers detected`() {
        assertTrue(SignatureDetector.isSigned("Authorization: AWS4-HMAC-SHA256 Credential=..."))
        assertTrue(SignatureDetector.isSigned("oauth_signature=\"abc\"&oauth_nonce=\"1\""))
    }

    @Test
    fun `ordinary request is not signed`() {
        assertFalse(SignatureDetector.isSigned("GET / HTTP/1.1\r\nHost: x\r\nCookie: sid={{COOKIE_SESSION_1}}\r\n\r\n"))
    }
}

class ToolPolicyTest {

    @Test
    fun `analyst classification counts hold`() {
        assertEquals(13, ToolPolicy.OUTPUT_MASK_TOOLS.size) // 11 read + 2 dual send/read
        assertEquals(6, ToolPolicy.INPUT_REHYDRATE_TOOLS.size)
        assertEquals(10, ToolPolicy.NEUTRAL_TOOLS.size)
        assertEquals(27, ToolPolicy.ALLOWED.size)
    }

    @Test
    fun `deny by default for unknown tools`() {
        assertFalse(ToolPolicy.isAllowed("some_new_upstream_tool"))
        assertFalse(ToolPolicy.isAllowed(""))
        assertTrue(ToolPolicy.isAllowed("get_proxy_http_history"))
    }

    @Test
    fun `dual send-read tools are in both mask and rehydrate sets`() {
        for (t in listOf("send_http1_request", "send_http2_request")) {
            assertTrue(ToolPolicy.needsOutputMasking(t), t)
            assertTrue(ToolPolicy.needsInputRehydration(t), t)
        }
    }

    @Test
    fun `read tools mask, send tools rehydrate, neutral tools pass`() {
        assertTrue(ToolPolicy.needsOutputMasking("get_active_editor_contents"))
        assertFalse(ToolPolicy.needsInputRehydration("get_active_editor_contents"))
        assertTrue(ToolPolicy.needsInputRehydration("create_repeater_tab"))
        assertFalse(ToolPolicy.needsOutputMasking("create_repeater_tab"))
        assertFalse(ToolPolicy.needsOutputMasking("url_encode"))
        assertFalse(ToolPolicy.needsInputRehydration("url_encode"))
    }
}
