package net.portswigger.mcp.tools

import io.mockk.mockk
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import net.portswigger.mcp.blinder.Blinder
import net.portswigger.mcp.blinder.Gateway
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/** LEAK-3: read-tool content that is not masking-verified TextContent must be withheld, not passed. */
class GatewayContentTest {

    @BeforeEach
    fun installGateway() {
        Blinder.gateway = Gateway()
    }

    @Test
    fun `text content is masked and non-text content is withheld with a notice`() {
        val nonText = mockk<ContentBlock>(relaxed = true) // e.g. ImageContent / structured content
        val input = listOf<ContentBlock>(
            TextContent("Set-Cookie: sid=REALSECRETVALUE0001; Path=/"),
            nonText
        )

        val out = maskContentBlocks("get_proxy_http_history", input)

        // The non-text block itself is not present in the output.
        assertFalse(out.contains(nonText), "unverified non-text block leaked through")

        // The text block was masked.
        val texts = out.filterIsInstance<TextContent>().map { it.text }
        assertTrue(texts.any { it.contains("{{COOKIE_SESSION_1}}") }, texts.toString())
        assertFalse(texts.any { it.contains("REALSECRETVALUE0001") }, "secret leaked: $texts")

        // A withheld notice is present.
        assertTrue(texts.any { it.contains("withheld") && it.contains("non-text") }, texts.toString())
    }

    @Test
    fun `all-text content passes through unchanged in shape (no notice)`() {
        val input = listOf<ContentBlock>(TextContent("GET /item1 HTTP/1.1"))
        val out = maskContentBlocks("get_proxy_http_history", input)
        assertEquals(1, out.size)
        assertTrue((out[0] as TextContent).text.contains("GET /item1"))
    }
}
