package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Live 2nd-wave tuning (real GitHub/jsonplaceholder responses):
 *  1) URL paths / all-pure-alpha tokens must never be masked (endpoint readability).
 *  2) Phone numbers are PII and are masked by default (like emails).
 *  3) scp/ssh remote syntax (git@host:path) is not a PII email.
 */
class LiveWave2Test {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    // (1) URL path in the request line and URL values stay readable.
    @Test
    fun `url paths are not masked`() {
        val reqLine = mask("GET /repos/PortSwigger/mcp-server HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        assertTrue(reqLine.contains("/repos/PortSwigger/mcp-server"), reqLine)
        assertFalse(reqLine.contains("{{SECRET"), reqLine)

        val jsonUrl = mask("""{"url":"https://api.github.com/orgs/PortSwigger/repos"}""")
        assertTrue(jsonUrl.contains("https://api.github.com/orgs/PortSwigger/repos"), jsonUrl)
        assertFalse(jsonUrl.contains("{{SECRET"), jsonUrl)
    }

    // (1-regression) A digit-bearing low-complexity token is still masked.
    @Test
    fun `slack-style token with digit segments is still masked`() {
        val out = mask("""{"k":"xoxb-1234-5678-abcdEFGH"}""")
        assertFalse(out.contains("xoxb-1234-5678-abcdEFGH"), out)
        assertTrue(out.contains("{{SECRET_1}}"), out)
    }

    // (2) Phone numbers are masked (NANP with extension, and E.164), with round-trip + consistency.
    @Test
    fun `phone numbers are masked by default`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"phone":"1-770-736-8031 x56442","alt":"1-770-736-8031 x56442","intl":"+14155552671"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("1-770-736-8031"), masked)
        assertFalse(masked.contains("+14155552671"), masked)
        assertTrue(masked.contains("{{PHONE_1}}"), masked)
        assertTrue(masked.contains("{{PHONE_2}}"), masked)
        // Same number -> same placeholder (referential consistency).
        assertEquals(2, Regex("\\{\\{PHONE_1}}").findAll(masked).count(), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `long continuous digit runs are not treated as phones`() {
        val out = mask("""{"ts":"1609459200000","id":"12345678901234"}""")
        assertTrue(out.contains("1609459200000"), out)
        assertTrue(out.contains("12345678901234"), out)
        assertFalse(out.contains("{{PHONE"), out)
    }

    // (3) scp/ssh remote (git@host:path) is not masked as an email; real emails still are.
    @Test
    fun `ssh scp remote is not masked as email but real emails are`() {
        val ssh = mask("""{"ssh_url":"git@github.com:PortSwigger/mcp-server.git"}""")
        assertTrue(ssh.contains("git@github.com:PortSwigger/mcp-server.git"), ssh)
        assertFalse(ssh.contains("{{EMAIL"), ssh)

        val email = mask("""{"email":"user@example.com"}""")
        assertFalse(email.contains("user@example.com"), email)
        assertTrue(email.contains("{{EMAIL_1}}"), email)
    }
}
