package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Round-3 leak-window fix: the `_`/`-` blanket exclusion (#09-3) re-opened a credential leak for
 * separator-containing 20-31 char secrets behind custom keys. Replaced by per-segment analysis:
 * a token is excluded only when EVERY separator segment is identifier-like (pure-alpha / pure-hex /
 * short version suffix); any mixed segment marks it a secret. This must re-close the leak without
 * regressing the #04 over-masking fixes (header names / snake_case keys / URL / UUID-off).
 */
class SegmentLeakWindowTest {

    private fun mask(text: String, uuids: Boolean = false) =
        Masker(Vault(), maskUuids = uuids).mask(text)

    // (a) The re-opened leak window: separator-containing high-entropy secrets are masked again.
    @Test
    fun `separator-containing high-entropy secrets behind custom keys are masked`() {
        val cases = listOf(
            "aZ9qP2xL_mK3nB6vC1wR8tY4",   // underscore, entropy ~4.58 (auditor repro)
            "aZ9qP2xL-mK3nB6vC1wR8tY4",   // hyphen variant
            "whsec_aZ9qP2xL7mK3nB6vC1wR", // Stripe webhook-style, 25 chars
            "xoxb-9qP2xL7mK3nB6vC1wR8"    // Slack-style, 24 chars
        )
        for (secret in cases) {
            val cookie = mask("Cookie: myapptok=$secret; theme=dark")
            assertFalse(cookie.contains(secret), "leaked in cookie: $cookie")
            assertTrue(cookie.contains("{{SECRET_1}}"), "not masked in cookie: $cookie")

            val json = mask("""{"myfield":"$secret"}""")
            assertFalse(json.contains(secret), "leaked in json: $json")
            assertTrue(json.contains("{{SECRET_1}}"), "not masked in json: $json")
        }
    }

    // (b) Identifiers stay readable: all-hex hyphenated trace id, snake_case url key, UUID (off).
    @Test
    fun `all-hex trace id and word identifiers remain unmasked`() {
        val traceId = "1a2b3c4d-5e6f7a8b-9c0d1e2f" // 26 chars, all segments pure-hex
        assertTrue(mask("X-Trace: $traceId").contains(traceId), "trace id over-masked")

        val out = mask("""{"data":"organization_repositories_url"}""")
        assertTrue(out.contains("organization_repositories_url"), out)

        val uuid = "550e8400-e29b-41d4-a716-446655440000"
        assertTrue(mask("""{"reqId":"$uuid"}""", uuids = false).contains(uuid), "UUID over-masked when toggle off")
    }

    // Version-suffixed identifier segments (v2) do not force masking.
    @Test
    fun `version-suffixed identifier is not masked`() {
        val out = mask("X-Meta: x_ratelimit_v2_reset")
        assertTrue(out.contains("x_ratelimit_v2_reset"), out)
    }

    // (c) Control: continuous (no-separator) secrets still masked; low-entropy filler still not.
    @Test
    fun `continuous secret masked, low-entropy filler not`() {
        val masked = mask("""{"k":"aZ9qP2xL7mK3nB6vC1wR8tY4"}""")
        assertTrue(masked.contains("{{SECRET_1}}"), masked)

        val filler = mask("""{"k":"aaaaaaaaaaaaaaaaaaaaaaaa"}""")
        assertFalse(filler.contains("{{SECRET"), filler)
    }
}
