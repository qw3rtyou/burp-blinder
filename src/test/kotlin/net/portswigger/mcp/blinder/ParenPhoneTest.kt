package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-7 PII leak: US parenthesized area-code phones `(254)954-1289` were not detected. Added a
 * dedicated `(NNN)NNN-NNNN` branch (with optional extension). Non-phone parenthesised numbers stay
 * readable.
 */
class ParenPhoneTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `parenthesized area-code phones are masked`() {
        for (p in listOf("(254)954-1289", "(775)976-6794 x41206", "(800) 555 0199")) {
            val out = mask("""{"phone":"$p"}""")
            assertFalse(out.contains(p), "phone leaked: $out")
            assertTrue(out.contains("{{PHONE_1}}"), "not masked: $out")
        }
    }

    @Test
    fun `non-phone parenthesised numbers are not masked`() {
        val out = mask("""{"year":"(2024)","amount":"(12,345)"}""")
        assertTrue(out.contains("(2024)"), out)
        assertTrue(out.contains("(12,345)"), out)
        assertFalse(out.contains("{{PHONE"), out)
    }

    @Test
    fun `parenthesized phone round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"a":"(254)954-1289","b":"(775)976-6794 x41206"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("(254)954-1289"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `existing phone formats still masked (regression)`() {
        assertTrue(mask("""{"p":"1-770-736-8031 x56442"}""").contains("{{PHONE_1}}"))
        assertTrue(mask("""{"p":"+81 9012345678"}""").contains("{{PHONE_1}}"))
        assertTrue(mask("""{"p":"+1 (415) 555-2671"}""").contains("{{PHONE_1}}"))
    }
}
