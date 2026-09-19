package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-9 PII leak: `@` written as `%40` in raw query/URL values evaded the email detector. The
 * percent-encoded-email pass masks it with a URL context so it is the same placeholder identity as
 * the decoded email and round-trips back to `%40`.
 */
class EncodedEmailTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `percent-encoded email in a url value is masked`() {
        val out = mask("""{"url":"https://api/x?email=bob%40mail.co.uk&y=2"}""")
        assertFalse(out.contains("bob%40mail.co.uk"), out)
        assertTrue(out.contains("{{EMAIL_1|u}}"), out)
        assertTrue(out.contains("&y=2"), out) // rest of query preserved
    }

    @Test
    fun `encoded and plaintext of the same email share one identity`() {
        val out = mask("""{"email":"carol@corp.com","enc":"carol%40corp.com"}""")
        assertFalse(out.contains("carol@corp.com"), out)
        assertFalse(out.contains("carol%40corp.com"), out)
        assertTrue(out.contains("\"email\":\"{{EMAIL_1}}\""), out)
        assertTrue(out.contains("\"enc\":\"{{EMAIL_1|u}}\""), out) // same base EMAIL_1
    }

    @Test
    fun `encoded email round-trips back to percent form`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"a":"dan%40evil.example.org","b":"https://h/x?email=eve%40corp.com"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("dan%40evil.example.org"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }

    @Test
    fun `plaintext email still masked and normal url untouched (regression)`() {
        assertTrue(mask("""{"e":"frank@corp.com"}""").contains("{{EMAIL_1}}"))
        val url = mask("visit http://a.com/path/to/page here")
        assertTrue(url.contains("http://a.com/path/to/page"), url)
        assertFalse(url.contains("{{EMAIL"), url)
    }
}
