package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression: an SSO session cookie `SESSIONID`
 * (a UUID, echoed in the `x-session-id` header) reached the agent channel in cleartext through
 * `get_proxy_http_history`. Root cause: that tool emits each HTTP message as an escaped-JSON string
 * whose `\r\n` are literal two-char escapes, not real newlines, so the `^`-anchored Cookie/Set-Cookie
 * header masking passes silently no-op; the UUID then slips past the (UUID-protected, default-off)
 * entropy pass and leaks. JSESSIONID happened to be masked only because its value is high-entropy.
 *
 * The two context-free passes (maskCookiePairsAnywhere / maskSessionHeadersAnywhere) close the blind
 * spot regardless of line context, while leaving non-sensitive cookies (locale/country/geo) readable.
 */
class EscapedHistoryCookieLeakTest {

    // Synthetic session id (shape only). A real captured value is never committed.
    private val uuid = "a1b2c3d4-e5f6-7890-abcd-ef0123456789"

    // NB: triple-quoted → the \r\n below are LITERAL backslash-r-backslash-n (4 chars), exactly as the
    // history tool serialises them. There are no real newlines in this string.
    private val escapedHistory =
        """{"response":"HTTP/1.1 200 OK\r\nset-cookie: SESSIONID=$uuid; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=lax\r\nx-session-id: $uuid\r\nset-cookie: locale=ko-KR; Domain=.example.com; SameSite=None; Secure\r\nset-cookie: country=KR; Domain=.example.com; SameSite=None; Secure\r\nContent-Length: 0\r\n\r\n"}"""

    @Test
    fun `SESSIONID session cookie in escaped-JSON history no longer leaks`() {
        val out = Masker(Vault()).mask(escapedHistory)
        assertFalse(out.contains(uuid), "session id leaked: $out")
        assertTrue(out.contains("SESSIONID={{"), "SESSIONID not masked: $out")
    }

    @Test
    fun `x-session-id header echo of the session id is masked too`() {
        val out = Masker(Vault()).mask(escapedHistory)
        assertTrue(out.contains("x-session-id: {{"), "x-session-id not masked: $out")
    }

    @Test
    fun `same session id gets one placeholder (reference consistency) and round-trips`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val masked = masker.mask(escapedHistory)
        assertFalse(masked.contains(uuid), masked)
        // The cookie value and the header echo are the same secret -> same placeholder.
        val cookiePh = Regex("""SESSIONID=(\{\{[^}]+}})""").find(masked)!!.groupValues[1]
        val headerPh = Regex("""x-session-id: (\{\{[^}]+}})""").find(masked)!!.groupValues[1]
        assertEquals(cookiePh, headerPh, "expected one placeholder for one value: $masked")
        // Byte-exact round-trip restores both occurrences.
        assertEquals(escapedHistory, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `non-sensitive cookies stay readable (no over-masking)`() {
        val out = Masker(Vault()).mask(escapedHistory)
        assertTrue(out.contains("locale=ko-KR"), "locale over-masked: $out")
        assertTrue(out.contains("country=KR"), "country over-masked: $out")
        // Cookie attributes must never be treated as cookie values.
        assertTrue(out.contains("Domain=.example.com"), out)
        assertTrue(out.contains("SameSite=lax"), out)
        assertTrue(out.contains("Path=/"), out)
    }

    @Test
    fun `real-newline Set-Cookie path still works (regression)`() {
        val raw = "HTTP/1.1 200 OK\r\nset-cookie: SESSIONID=$uuid; Path=/; Secure; HttpOnly; SameSite=lax\r\n\r\n"
        val out = Masker(Vault()).mask(raw)
        assertFalse(out.contains(uuid), out)
        assertTrue(out.contains("SESSIONID={{"), out)
    }

    // ---- account PII leak (an authenticated /api/session/user-style response) --------------------

    private val userId = "3cf99f04-e44d-4ae8-95d4-0555d90cd95f"

    @Test
    fun `account PII in authenticated API body and X-UserId header is masked`() {
        val history =
            """{"response":"HTTP/1.1 200 OK\r\nX-UserId: $userId\r\nContent-Type: application/json\r\n\r\n{\"user_id\":\"$userId\",\"user_name\":\"Hong Gildong\",\"account_name\":\"Hong Gildong\",\"country_code\":\"KR\"}"}"""
        val out = Masker(Vault()).mask(history)
        assertFalse(out.contains(userId), "user_id leaked: $out")
        assertFalse(out.contains("Hong Gildong"), "account name leaked: $out")
        assertTrue(out.contains("X-UserId: {{PII_"), "X-UserId not masked: $out")
        // Structure preserved (non-sensitive fields readable).
        assertTrue(out.contains("\\\"country_code\\\":\\\"KR\\\""), out)
    }

    @Test
    fun `user_id echoed inside a URL is scrubbed by reference consistency`() {
        val history =
            """{"response":"HTTP/1.1 200 OK\r\nX-UserId: $userId\r\n\r\n{\"user_id\":\"$userId\",\"np_profile_image_url\":\"https://img.example.com/p/$userId?size=normal\",\"country_code\":\"KR\"}"}"""
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val out = masker.mask(history)
        assertFalse(out.contains(userId), "user_id echo leaked in URL: $out")
        assertTrue(out.contains("https://img.example.com/p/{{PII_1}}?size=normal"), "URL structure not preserved: $out")
        assertEquals(history, rehydrator.rehydrate(out).text) // byte-exact round-trip
    }

    @Test
    fun `short vaulted values do not blanket-scrub unrelated text`() {
        // A short masked value must never be reference-scrubbed across the document.
        val out = Masker(Vault()).mask("""{"password":"ab","note":"the value ab appears here too"}""")
        assertTrue(out.contains("the value ab appears here too"), "short value over-scrubbed: $out")
    }

    @Test
    fun `display-name keys (userName externalAccountName) are masked`() {
        // Authenticated account APIs can leak a real name via these keys.
        val out = Masker(Vault()).mask(
            """{"userId":"x","userName":"Hong Gildong","externalAccountName":"Hong Gildong","countryCode":"KR"}"""
        )
        assertFalse(out.contains("Hong Gildong"), "display name leaked: $out")
        assertTrue(out.contains("\"countryCode\":\"KR\""), "non-PII over-masked: $out")
    }

    @Test
    fun `session-suffix key (adminSession) is masked`() {
        // A camelCase key ending in *Session carries a session id and must be masked.
        val gs = "898f5bdc-0f77-40f1-992c-2e950a2e0480"
        val out = Masker(Vault()).mask("""{"adminSession":"$gs"}""")
        assertFalse(out.contains(gs), "adminSession leaked: $out")
        assertTrue(out.contains("\"adminSession\":\"{{"), "adminSession not masked: $out")
    }

    @Test
    fun `username in a URL query is not masked (JSON-only policy)`() {
        // The name-key masking is JSON-body only; a query/form `username` stays readable so recon and
        // IDOR analysis over URLs are unaffected.
        val out = Masker(Vault()).mask("GET /profile?username=admin HTTP/1.1\r\nHost: x\r\n\r\n")
        assertTrue(out.contains("username=admin"), "query username over-masked: $out")
    }

    @Test
    fun `request Cookie header carrying SESSIONID (escaped) is masked`() {
        val req =
            """{"request":"GET / HTTP/1.1\r\nHost: www.example.com\r\nCookie: device-id=dev; SESSIONID=$uuid; country=KR; locale=ko-KR\r\n\r\n"}"""
        val out = Masker(Vault()).mask(req)
        assertFalse(out.contains(uuid), out)
        assertTrue(out.contains("country=KR") && out.contains("locale=ko-KR"), out)
    }
}
