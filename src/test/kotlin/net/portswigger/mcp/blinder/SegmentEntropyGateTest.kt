package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Round-4 residual leak-window fix: tokens whose segments were each individually low-complexity
 * (pure-alpha / pure-hex / pure-digit / version-suffix) slipped through even when the whole token
 * was high-entropy. A 2nd entropy gate (length*entropy) plus a version-suffix-once limit now masks
 * mixed low-complexity secrets while keeping structural identifiers and hex trace-ids readable.
 */
class SegmentEntropyGateTest {

    private fun mask(text: String, uuids: Boolean = false) =
        Masker(Vault(), maskUuids = uuids).mask(text)

    // Must MASK: all-simple-segment tokens whose whole is high-entropy (round-4 leak repros).
    @Test
    fun `low-complexity-segment but high-entropy tokens are masked`() {
        val secrets = listOf(
            "xoxb-1234-5678-abcdEFGH",     // acceptance value (Slack-style)
            "whsec_1a2b3c4d5e6f7a8b9c0d",  // all-hex body behind alpha prefix
            "sk-abc12-DEF34-ghi56-JKL78",  // version-suffix laundering
            "1234-5678-abcdEFGH-90ab"      // digit/hex/alpha mix
        )
        for (s in secrets) {
            val cookie = mask("Cookie: myapptok=$s; theme=dark")
            assertFalse(cookie.contains(s), "leaked in cookie: $cookie")
            assertTrue(cookie.contains("{{SECRET_1}}"), "not masked in cookie: $cookie")

            val json = mask("""{"myfield":"$s"}""")
            assertFalse(json.contains(s), "leaked in json: $json")
            assertTrue(json.contains("{{SECRET_1}}"), "not masked in json: $json")
        }
    }

    // Must NOT mask: structural identifiers / low-entropy id-like tokens (no #04 regression).
    @Test
    fun `structural and low-entropy identifiers remain readable`() {
        val keep = listOf(
            "x_ratelimit_v2_reset",           // version suffix, low entropy
            "organization_repositories_url",  // pure-alpha snake_case
            "content_security_policy",        // pure-alpha snake_case
            "1a2b3c4d-5e6f7a8b-9c0d1e2f"       // all-hex trace id (accepted LOW trade-off)
        )
        for (id in keep) {
            val out = mask("""{"field":"$id"}""")
            assertTrue(out.contains(id), "over-masked: $out")
        }
    }

    @Test
    fun `header names and uuid-off remain readable`() {
        val hdr = mask("Access-Control-Allow-Origin: *\r\nContent-Security-Policy: default-src 'self'\r\n\r\n")
        assertTrue(hdr.contains("Access-Control-Allow-Origin"), hdr)
        assertTrue(hdr.contains("Content-Security-Policy"), hdr)
        assertFalse(hdr.contains("{{SECRET"), hdr)

        val uuid = "550e8400-e29b-41d4-a716-446655440000"
        assertTrue(mask("""{"reqId":"$uuid"}""").contains(uuid), "UUID over-masked when toggle off")
    }
}
