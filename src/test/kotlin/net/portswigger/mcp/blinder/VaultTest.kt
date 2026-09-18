package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VaultTest {

    @Test
    fun `same value yields same placeholder (referential consistency)`() {
        val vault = Vault()
        val a = vault.placeholderFor("session-abc", TokenType.COOKIE_SESSION)
        val b = vault.placeholderFor("session-abc", TokenType.COOKIE_SESSION)
        assertEquals(a, b)
        assertEquals("{{COOKIE_SESSION_1}}", a)
    }

    @Test
    fun `different values yield different placeholders`() {
        val vault = Vault()
        val a = vault.placeholderFor("value-1", TokenType.BEARER)
        val b = vault.placeholderFor("value-2", TokenType.BEARER)
        assertNotEquals(a, b)
        assertEquals("{{BEARER_1}}", a)
        assertEquals("{{BEARER_2}}", b)
    }

    @Test
    fun `ids increment per type independently`() {
        val vault = Vault()
        assertEquals("{{EMAIL_1}}", vault.placeholderFor("a@b.com", TokenType.EMAIL))
        assertEquals("{{COOKIE_SESSION_1}}", vault.placeholderFor("s1", TokenType.COOKIE_SESSION))
        assertEquals("{{EMAIL_2}}", vault.placeholderFor("c@d.com", TokenType.EMAIL))
    }

    @Test
    fun `reverse lookup returns real value`() {
        val vault = Vault()
        val ph = vault.placeholderFor("realsecret", TokenType.SECRET)
        assertEquals("realsecret", vault.realFor(ph))
        assertNull(vault.realFor("{{SECRET_999}}"))
    }

    @Test
    fun `clear empties the vault`() {
        val vault = Vault()
        vault.placeholderFor("x", TokenType.SECRET)
        assertTrue(vault.size() > 0)
        vault.clear()
        assertEquals(0, vault.size())
        // After clear, ids restart.
        assertEquals("{{SECRET_1}}", vault.placeholderFor("y", TokenType.SECRET))
    }
}
