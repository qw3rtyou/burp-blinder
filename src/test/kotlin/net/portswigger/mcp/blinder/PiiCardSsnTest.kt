package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Live wave-3 PII under-masking fix: credit cards (Luhn-gated), SSN / national-id (shape + key),
 * and phone country-code prefixes. PII protection is this tool's reason to exist, so these are ON
 * by default like email/phone.
 */
class PiiCardSsnTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `credit card is masked by key name and by Luhn-valid shape`() {
        val byKey = mask("""{"bank":{"cardNumber":"3693233511855044"}}""") // Diners, Luhn valid
        assertFalse(byKey.contains("3693233511855044"), byKey)
        assertTrue(byKey.contains("{{CARD_1"), byKey)

        val byShape = mask("""{"note":"pay to 4111 1111 1111 1111 today"}""") // Visa test, Luhn valid
        assertFalse(byShape.contains("4111 1111 1111 1111"), byShape)
        assertTrue(byShape.contains("{{CARD_1"), byShape)
    }

    @Test
    fun `luhn-invalid and continuous digit runs are not masked as cards`() {
        val invalid = mask("""{"rand":"1234 5678 9012 3456"}""") // Luhn invalid
        assertTrue(invalid.contains("1234 5678 9012 3456"), invalid)

        val digits = mask("""{"ts":"1609459200000","id":"12345678901234","amount":"1234567890123"}""")
        assertTrue(digits.contains("1609459200000") && digits.contains("12345678901234") && digits.contains("1234567890123"), digits)
        assertFalse(digits.contains("{{CARD"), digits)
    }

    @Test
    fun `ssn is masked by key name and by standard shape`() {
        val byKey = mask("""{"ssn":"900-590-289"}""") // non-standard 3-3-3, caught by key
        assertFalse(byKey.contains("900-590-289"), byKey)
        assertTrue(byKey.contains("{{SSN_1"), byKey)

        val byShape = mask("""{"note":"id 123-45-6789 on file"}""") // standard 3-2-4 shape
        assertFalse(byShape.contains("123-45-6789"), byShape)
        assertTrue(byShape.contains("{{SSN_1"), byShape)
    }

    @Test
    fun `phone with country-code prefix is fully masked`() {
        val out = mask("""{"phone":"+81 9012345678"}""")
        assertFalse(out.contains("+81 9012345678"), out)
        assertTrue(out.contains("{{PHONE_1}}"), out)
    }

    @Test
    fun `card and phone round-trip exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"card":"4111 1111 1111 1111","phone":"+81 9012345678"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("4111 1111 1111 1111"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `regression - slack token still masked, url path and header still readable`() {
        assertTrue(mask("""{"k":"xoxb-1234-5678-abcdEFGH"}""").contains("{{SECRET_1}}"))
        assertTrue(mask("GET /repos/PortSwigger/mcp-server HTTP/1.1\r\nHost: x\r\n\r\n").contains("/repos/PortSwigger/mcp-server"))
        assertTrue(mask("Access-Control-Allow-Origin: *\r\n\r\n").contains("Access-Control-Allow-Origin"))
    }
}
