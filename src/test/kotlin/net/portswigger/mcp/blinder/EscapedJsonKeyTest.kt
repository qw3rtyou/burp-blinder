package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-10b: double-encoded JSON (a JSON body serialised into a JSON string) escapes quotes as `\"`,
 * so key-based masking must also recognise `\"key\":\"value\"`. Value only is masked; escapes and
 * structure preserved; byte-exact round-trip.
 */
class EscapedJsonKeyTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `escaped json sensitive value is masked, escapes preserved`() {
        val out = mask("""{"data":"{\"DB_PASSWORD\":\"Pr0dDbP4ss!\"}"}""")
        assertFalse(out.contains("Pr0dDbP4ss!"), out)
        assertTrue(out.contains("""{\"DB_PASSWORD\":\"{{SECRET_1}}\"}"""), out)
    }

    @Test
    fun `escaped json masks sensitive key only, non-sensitive preserved`() {
        val out = mask("""{"body":"{\"api_secret\":\"sk_abc123\",\"label\":\"admin\"}"}""")
        assertFalse(out.contains("sk_abc123"), out)
        assertTrue(out.contains("""\"api_secret\":\"{{SECRET_1}}\""""), out)
        assertTrue(out.contains("""\"label\":\"admin\""""), out)
    }

    @Test
    fun `plain json still masked (regression) and non-sensitive escaped key untouched`() {
        assertTrue(mask("""{"DB_PASSWORD":"Pr0dDbP4ss!"}""").contains("{{SECRET_1|j}}"))
        val out = mask("""{"log":"{\"label\":\"admin\",\"note\":\"ok\"}"}""")
        assertTrue(out.contains("""\"label\":\"admin\""""), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    @Test
    fun `escaped json masking round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"data":"{\"DB_PASSWORD\":\"Pr0dDbP4ss!\",\"ACCESS_TOKEN\":\"at_xyz789\"}"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("Pr0dDbP4ss!"), masked)
        assertFalse(masked.contains("at_xyz789"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
