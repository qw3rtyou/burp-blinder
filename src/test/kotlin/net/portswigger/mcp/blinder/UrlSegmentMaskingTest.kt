package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * #19: URL over-masking. A sensitive path segment must not drag the surrounding readable path
 * structure into one placeholder. Masking respects `/` segment boundaries: structural (pure-alpha)
 * segments are preserved, only sensitive segments are concealed. Query values stay masked.
 */
class UrlSegmentMaskingTest {

    private fun sel() = Masker(Vault(), mode = MaskingMode.SELECTIVE)

    @Test
    fun `bbc-style url keeps path structure and masks only the id`() {
        val vault = Vault()
        val masker = Masker(vault, mode = MaskingMode.SELECTIVE)
        val rehydrator = Rehydrator(vault)
        val real = "link: https://www.bbc.co.uk/news/articles/cx2gx8n8e5po end"
        val out = masker.mask(real)
        assertFalse(out.contains("cx2gx8n8e5po"), out)
        assertTrue(out.contains("https://www.bbc.co.uk/news/articles/{{SECRET_1}}"), out)
        assertEquals(real, rehydrator.rehydrate(out).text)
    }

    @Test
    fun `pure-alpha url is fully preserved (github link header)`() {
        val out = sel().mask("<https://api.github.com/repos/PortSwigger/mcp-server/contributors?per_page=2>; rel=\"next\"")
        assertTrue(out.contains("https://api.github.com/repos/PortSwigger/mcp-server/contributors"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    @Test
    fun `request-line path preserved (regression)`() {
        val out = sel().mask("GET /repos/PortSwigger/mcp-server HTTP/1.1\r\nHost: x\r\n\r\n")
        assertTrue(out.contains("/repos/PortSwigger/mcp-server"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    @Test
    fun `query value still masked while path preserved`() {
        val out = sel().mask("cb: https://host/callback?token=ghp_16C7e42F292c6912E7710c838347Ae178B4a&x=1")
        assertFalse(out.contains("ghp_16C7e42F292c6912E7710c838347Ae178B4a"), out)
        assertTrue(out.contains("https://host/callback?token={{SECRET_1}}"), out)
        assertTrue(out.contains("&x=1"), out)
    }

    @Test
    fun `strong secret path segment is masked, structure preserved`() {
        val hex40 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        val out = sel().mask("path https://h/download/$hex40/file end")
        assertFalse(out.contains(hex40), out)
        assertTrue(out.contains("https://h/download/{{SECRET_1}}/file"), out)
    }

    @Test
    fun `strict also keeps path structure but conceals the value segment`() {
        val vault = Vault()
        val masker = Masker(vault, mode = MaskingMode.STRICT)
        val rehydrator = Rehydrator(vault)
        val real = "link: https://www.bbc.co.uk/news/articles/cx2gx8n8e5po end"
        val out = masker.mask(real)
        assertFalse(out.contains("cx2gx8n8e5po"), out)
        assertTrue(out.contains("/news/articles/{{SECRET_1}}"), out)
        assertEquals(real, rehydrator.rehydrate(out).text)
    }
}
