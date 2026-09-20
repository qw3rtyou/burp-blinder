package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * #23 internal topology masking: private/internal IPs and internal hostnames are concealed even in
 * SELECTIVE (default on), while public IPs and public domains stay readable.
 */
class TopologyMaskingTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `private and internal ips are masked in selective`() {
        for (ip in listOf("10.1.2.3", "192.168.1.50", "172.16.5.9", "127.0.0.1", "169.254.1.1", "fe80::1", "::1", "fc00::abcd")) {
            val out = mask("addr=$ip;")
            assertFalse(out.contains(ip), "internal ip leaked: $out")
            assertTrue(out.contains("{{IP_1}}"), "not masked: $out")
        }
    }

    @Test
    fun `public ip is not masked in selective (default)`() {
        val out = mask("dns 8.8.8.8 and 203.0.113.9 ok")
        assertTrue(out.contains("8.8.8.8"), out)
        assertTrue(out.contains("203.0.113.9"), out)
        assertFalse(out.contains("{{IP"), out)
    }

    @Test
    fun `maskPrivateIps=false leaves internal ip readable`() {
        val out = Masker(Vault(), maskPrivateIps = false).mask("addr 10.1.2.3 end")
        assertTrue(out.contains("10.1.2.3"), out)
    }

    @Test
    fun `internal host masked, url structure preserved`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = "deploy https://jenkins.corp.local:8080/job/deploy now"
        val out = masker.mask(real)
        assertFalse(out.contains("jenkins.corp.local"), out)
        assertTrue(out.contains("https://{{IHOST_1}}:8080/job/deploy"), out)
        assertEquals(real, rehydrator.rehydrate(out).text)
    }

    @Test
    fun `internal suffix hosts masked, public domains preserved (label boundary)`() {
        val out = mask("""{"a":"db.internal","b":"api.github.com","c":"mycorp.com","d":"printer.home.arpa","e":"db.internal.example.com"}""")
        assertFalse(out.contains("\"db.internal\""), out)
        assertTrue(out.contains("db.internal.example.com"), out) // public (.com), not masked despite containing 'internal'
        assertTrue(out.contains("api.github.com"), out)
        assertTrue(out.contains("mycorp.com"), out)              // '.corp' suffix must not match mycorp.com
        assertFalse(out.contains("printer.home.arpa"), out)      // home.arpa masked
    }

    @Test
    fun `internal host reference consistency and cookie domain`() {
        val out = mask("Host: gitlab.corp\r\nSet-Cookie: s=x; Domain=.gitlab.corp\r\n\r\n")
        // Both occurrences of gitlab.corp collapse to one placeholder identity.
        assertEquals(2, Regex("\\{\\{IHOST_1}}").findAll(out).count(), out)
        assertFalse(out.contains("gitlab.corp"), out)
    }

    @Test
    fun `strict masks internal host too`() {
        val out = Masker(Vault(), mode = MaskingMode.STRICT).mask("url https://ci.lan/build")
        assertFalse(out.contains("ci.lan"), out)
        assertTrue(out.contains("https://{{IHOST_1}}/build"), out)
    }
}
