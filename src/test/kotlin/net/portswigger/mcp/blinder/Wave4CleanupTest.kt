package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.x cleanup: (1) phone country-code prefix is included in the mask, (2) the same Bearer token
 * collapses to one placeholder identity across the request header and a JSON echo.
 */
class Wave4CleanupTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `phone country-code prefix is masked as one unit`() {
        val cases = listOf("+81 9012345678", "+1 (415) 555-2671", "+44-20-7946-0958")
        for (p in cases) {
            val out = mask("""{"phone":"$p"}""")
            assertFalse(out.contains(p), "prefix/number leaked: $out")
            assertFalse(out.contains("+"), "country-code prefix left outside mask: $out")
            assertTrue(out.contains("{{PHONE_1}}"), "not masked: $out")
        }
    }

    @Test
    fun `international phone round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"a":"+81 9012345678","b":"+44-20-7946-0958"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("+81"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `same bearer token is one placeholder across header and json echo`() {
        val token = "abc123def456ghi789jkl012"
        val req = "GET /x HTTP/1.1\r\n" +
                "Authorization: Bearer $token\r\n\r\n" +
                """{"headers":{"authorization":"Bearer $token"}}"""
        val out = mask(req)
        assertFalse(out.contains(token), "token leaked: $out")
        // Both occurrences share the same base identity BEARER_1 (no SECRET fragmentation).
        assertTrue(out.contains("Bearer {{BEARER_1}}"), out)
        assertTrue(out.contains("{{BEARER_1|j}}"), out)
        assertFalse(out.contains("{{SECRET"), "fragmented into a second placeholder: $out")
    }

    @Test
    fun `bearer header and echo round-trip exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val token = "abc123def456ghi789jkl012"
        val real = "Authorization: Bearer $token\r\n\r\n{\"authorization\":\"Bearer $token\"}"
        val masked = masker.mask(real)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `regression - continuous digit runs still not phones, slack token still masked`() {
        val digits = mask("""{"ts":"1609459200000","id":"12345678901234"}""")
        assertFalse(digits.contains("{{PHONE"), digits)
        assertTrue(mask("""{"k":"xoxb-1234-5678-abcdEFGH"}""").contains("{{SECRET_1}}"))
    }
}
