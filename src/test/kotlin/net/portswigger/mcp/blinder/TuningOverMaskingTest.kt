package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Live-tuning regression (04_live_tuning_findings.md): the LEAK-1 fix must keep masking real
 * secrets while no longer over-masking structural identifiers (header names, snake_case keys,
 * URL paths, UUIDs).
 */
class TuningOverMaskingTest {

    private fun mask(text: String, uuids: Boolean = false): String =
        Masker(Vault(), maskUuids = uuids).mask(text)

    // (a) HTTP header names are not masked.
    @Test
    fun `http header names are not masked`() {
        val out = mask(
            "Access-Control-Allow-Origin: *\r\n" +
                "Strict-Transport-Security: max-age=31536000\r\n" +
                "Content-Security-Policy: default-src 'self'\r\n" +
                "X-Content-Type-Options: nosniff\r\n" +
                "Access-Control-Allow-Credentials: true\r\n\r\n"
        )
        for (name in listOf(
            "Access-Control-Allow-Origin", "Strict-Transport-Security", "Content-Security-Policy",
            "X-Content-Type-Options", "Access-Control-Allow-Credentials"
        )) {
            assertTrue(out.contains(name), "$name was over-masked: $out")
        }
        assertFalse(out.contains("{{SECRET"), out)
    }

    // (b) Long snake_case JSON keys (and their URL values) are not masked.
    @Test
    fun `snake_case json keys are not masked`() {
        val out = mask(
            """{"organization_repositories_url":"https://api.github.com/orgs/x/repos","repository_search_url":"https://api.github.com/search/repositories"}"""
        )
        assertTrue(out.contains("organization_repositories_url"), out)
        assertTrue(out.contains("repository_search_url"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    // (c) UUID toggle: OFF leaves UUID readable, ON masks it (round-trip exact).
    @Test
    fun `uuid is not masked when toggle is off`() {
        val out = mask("""{"X-Request-Id":"550e8400-e29b-41d4-a716-446655440000"}""", uuids = false)
        assertTrue(out.contains("550e8400-e29b-41d4-a716-446655440000"), out)
    }

    @Test
    fun `uuid is masked and round-trips when toggle is on`() {
        val vault = Vault()
        val masker = Masker(vault, maskUuids = true)
        val rehydrator = Rehydrator(vault)
        val real = """{"X-Request-Id":"550e8400-e29b-41d4-a716-446655440000"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("550e8400-e29b-41d4-a716-446655440000"), masked)
        assertTrue(masked.contains("{{UUID_1}}"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    // (d) LEAK-1 value is still masked.
    @Test
    fun `leak1 high-entropy value is still masked behind custom key`() {
        val out = mask("""{"myfield":"aZ9qP2xL7mK3nB6vC1wR8tY4"}""")
        assertFalse(out.contains("aZ9qP2xL7mK3nB6vC1wR8tY4"), out)
        assertTrue(out.contains("{{SECRET_1}}"), out)
    }

    // (e) Real secrets are still masked.
    @Test
    fun `real secrets are still masked`() {
        val cases = mapOf(
            "GitHub PAT" to "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "AWS access key" to "AKIAZK7Q4XR9PLMN2WYB",
            "Stripe secret" to "sk_live_51H8xqR2mNpQ7wYzA4bC6dE9",
            "continuous random 24" to "aZ9qP2xL7mK3nB6vC1wR8tY4"
        )
        for ((label, secret) in cases) {
            val out = mask("""{"customtok":"$secret"}""")
            assertFalse(out.contains(secret), "$label leaked: $out")
            assertTrue(out.contains("{{SECRET_1}}"), "$label not masked: $out")
        }
    }

    // (f) The same value in two encoding/contexts collapses to a single placeholder identity.
    @Test
    fun `same value across encodings uses one placeholder (de-fragmentation)`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = "GET /x?session=tok%2Fval HTTP/1.1\r\n" +
                "Host: x\r\n" +
                "Set-Cookie: sessionid=tok/val; Path=/\r\n\r\n"
        val masked = masker.mask(real)

        assertFalse(masked.contains("tok/val"), masked)
        // One identity (COOKIE_SESSION_1), differing only by encoding suffix — no fragmented SECRET.
        assertTrue(masked.contains("{{COOKIE_SESSION_1}}"), masked)      // raw Set-Cookie
        assertTrue(masked.contains("{{COOKIE_SESSION_1|u}}"), masked)   // URL-encoded query
        assertFalse(masked.contains("{{SECRET"), "fragmented into a second placeholder: $masked")
        assertFalse(masked.contains("COOKIE_SESSION_2"), masked)

        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    // Structural identifiers as VALUES (not just keys) are also excluded.
    @Test
    fun `structural identifier values are not masked`() {
        val out = mask("""{"type":"organization_repositories_url","path":"com/login/oauth/authorize"}""")
        assertTrue(out.contains("organization_repositories_url"), out)
        assertTrue(out.contains("com/login/oauth/authorize"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }
}
