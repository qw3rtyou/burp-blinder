package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DynamicTokenTest {

    @Test
    fun `store auto returns latest captured token`() {
        val store = DynamicTokenStore()
        store.putCsrf("csrf", "one")
        store.putCsrf("csrf", "two")
        assertEquals("two", store.csrf("auto"))
        assertEquals("two", store.csrf("csrf"))
        assertNull(store.csrf("missing"))
    }

    @Test
    fun `extractor captures csrf from hidden input`() {
        val store = DynamicTokenStore()
        DynamicTokenExtractor(store).observe(
            """<form><input type="hidden" name="csrf_token" value="HID-9animal-123"></form>"""
        )
        assertEquals("HID-9animal-123", store.csrf("auto"))
    }

    @Test
    fun `extractor captures csrf from meta tag`() {
        val store = DynamicTokenStore()
        DynamicTokenExtractor(store).observe("""<meta name="csrf-token" content="META-TOK-77">""")
        assertEquals("META-TOK-77", store.csrf("auto"))
    }

    @Test
    fun `extractor captures csrf from set-cookie and json`() {
        val store = DynamicTokenStore()
        DynamicTokenExtractor(store).observe("HTTP/1.1 200 OK\r\nSet-Cookie: XSRF-TOKEN=COOKIE-CSRF-1; Path=/\r\n\r\n")
        assertEquals("COOKIE-CSRF-1", store.csrf("auto"))

        val store2 = DynamicTokenStore()
        DynamicTokenExtractor(store2).observe("""{"csrfToken":"JSON-CSRF-2","other":1}""")
        assertEquals("JSON-CSRF-2", store2.csrf("auto"))
    }

    @Test
    fun `configurable rule hook can capture site-specific tokens`() {
        val store = DynamicTokenStore()
        val rule = DynamicTokenExtractor.Rule { response ->
            Regex("""RequestToken=([A-Z0-9]+)""").find(response)?.let { listOf("custom" to it.groupValues[1]) } ?: emptyList()
        }
        DynamicTokenExtractor(store, listOf(rule)).observe("... RequestToken=ABC123 ...")
        assertEquals("ABC123", store.csrf("custom"))
    }

    @Test
    fun `captured csrf is never surfaced but is injected at send time`() {
        val gateway = Gateway()
        // Live response observed by the HttpHandler.
        gateway.captureResponse("""<input type="hidden" name="csrf_token" value="LIVE-TOKEN-55">""")
        // Agent composes a request with the managed placeholder (never sees the value).
        val outcome = gateway.rehydrateInput(
            "send_http1_request",
            "POST /transfer HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf_token={{CSRF:auto}}&amount=100"
        )
        assertTrue(outcome.text.contains("csrf_token=LIVE-TOKEN-55"), outcome.text)
        assertTrue(outcome.residual.isEmpty())
    }
}
