package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Round-trip identity per encoding context: a real literal, replaced by a context-tagged
 * placeholder, must rehydrate back to the exact original bytes. Placeholders are emitted exactly as
 * the Masker would emit them for each context.
 */
class RehydratorRoundTripTest {

    private fun masked(vault: Vault, value: String, type: TokenType, chain: List<Encoding>): String {
        val base = vault.placeholderFor(value, type)
        return Placeholder.emit(base, chain)
    }

    @Test
    fun `raw context round-trips`() {
        val vault = Vault()
        val rehydrator = Rehydrator(vault)
        val value = "s3ss10n-cookie-value"
        val real = "Cookie: session=$value"
        val maskedText = "Cookie: session=${masked(vault, value, TokenType.COOKIE_SESSION, emptyList())}"
        val result = rehydrator.rehydrate(maskedText)
        assertEquals(real, result.text)
        assertFalse(result.hasResidual)
    }

    @Test
    fun `url context round-trips`() {
        val vault = Vault()
        val rehydrator = Rehydrator(vault)
        val value = "a b&c=d/e"
        val literal = Encoding.URL.encode(value)
        val real = "GET /p?token=$literal HTTP/1.1"
        val maskedText = "GET /p?token=${masked(vault, value, TokenType.SECRET, listOf(Encoding.URL))} HTTP/1.1"
        assertEquals(real, rehydrator.rehydrateText(maskedText))
    }

    @Test
    fun `base64 context round-trips`() {
        val vault = Vault()
        val rehydrator = Rehydrator(vault)
        val value = "user:sup3rp@ss"
        val literal = Encoding.BASE64.encode(value)
        val real = "Authorization: Basic $literal"
        val maskedText = "Authorization: Basic ${masked(vault, value, TokenType.BASIC, listOf(Encoding.BASE64))}"
        assertEquals(real, rehydrator.rehydrateText(maskedText))
    }

    @Test
    fun `json context round-trips with escaping`() {
        val vault = Vault()
        val rehydrator = Rehydrator(vault)
        val value = """he said "hi"\ and left"""
        val literal = Encoding.JSON.encode(value)
        val real = """{"note":"$literal"}"""
        val maskedText = """{"note":"${masked(vault, value, TokenType.SECRET, listOf(Encoding.JSON))}"}"""
        assertEquals(real, rehydrator.rehydrateText(maskedText))
    }

    @Test
    fun `nested base64-of-url chain round-trips`() {
        val vault = Vault()
        val rehydrator = Rehydrator(vault)
        val value = "token value/with+chars"
        // chain innermost-first [BASE64, URL] => urlEncode(base64(value))
        val chain = listOf(Encoding.BASE64, Encoding.URL)
        val literal = chain.applyEncode(value)
        val real = "GET /cb?state=$literal HTTP/2"
        val maskedText = "GET /cb?state=${masked(vault, value, TokenType.SECRET, chain)} HTTP/2"
        assertEquals(real, rehydrator.rehydrateText(maskedText))
    }

    @Test
    fun `unknown placeholder is reported as residual and left intact`() {
        val vault = Vault()
        val rehydrator = Rehydrator(vault)
        val result = rehydrator.rehydrate("value={{SECRET_42}}")
        assertTrue(result.hasResidual)
        assertEquals("value={{SECRET_42}}", result.text)
    }

    @Test
    fun `managed CSRF placeholder resolves from dynamic store`() {
        val vault = Vault()
        val store = DynamicTokenStore()
        store.putCsrf("csrf_token", "LIVE-CSRF-9animal")
        val rehydrator = Rehydrator(vault, store)
        val result = rehydrator.rehydrate("csrf={{CSRF:auto}}")
        assertEquals("csrf=LIVE-CSRF-9animal", result.text)
        assertFalse(result.hasResidual)
    }
}
