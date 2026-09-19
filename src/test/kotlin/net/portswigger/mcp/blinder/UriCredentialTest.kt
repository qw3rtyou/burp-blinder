package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-8 leak: passwords embedded in connection-string URIs (`scheme://user:pass@host`) were left
 * in the clear. The URI-credentials pass masks the password only, preserving scheme/user/host/port
 * /path so the connection structure stays readable.
 */
class UriCredentialTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `connection-string passwords are masked, structure and user preserved`() {
        val cases = mapOf(
            "postgres://admin:S3cr3tP4ss@db.example.com:5432/prod" to "S3cr3tP4ss",
            "jdbc:mysql://root:hunter2pw@10.0.0.1:3306/app" to "hunter2pw",
            "mongodb://svc:MongoPw99@mongo:27017/db" to "MongoPw99",
            "redis://default:Redd1sPw@cache:6379/0" to "Redd1sPw",
            "amqp://guest:guestpw@rabbit:5672/vhost" to "guestpw",
            "ftp://user:pass1234@files.example.com" to "pass1234"
        )
        for ((uri, password) in cases) {
            val out = mask("""{"url":"$uri"}""")
            assertFalse(out.contains(password), "password leaked: $out")
            assertTrue(out.contains("{{SECRET_1}}"), "not masked: $out")
            // Structure preserved: scheme prefix, user and host survive.
            assertTrue(out.contains(uri.substringBefore(":$password")), "structure lost: $out")
            assertTrue(out.contains(uri.substringAfter("$password@").let { "@$it" }), "host/path lost: $out")
        }
    }

    @Test
    fun `username is preserved`() {
        val out = mask("db=postgres://admin:S3cr3tP4ss@db:5432/prod")
        assertTrue(out.contains("postgres://admin:{{SECRET_1}}@db:5432/prod"), out)
    }

    @Test
    fun `url without userinfo is not masked`() {
        val out = mask("""{"a":"http://example.com/a:b:c","b":"http://host:8080/path?x=1"}""")
        assertTrue(out.contains("http://example.com/a:b:c"), out)
        assertTrue(out.contains("http://host:8080/path?x=1"), out)
        assertFalse(out.contains("{{SECRET"), out)
    }

    @Test
    fun `connection string round-trips exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"pg":"postgres://admin:S3cr3tP4ss@db.example.com:5432/prod","my":"jdbc:mysql://root:hunter2pw@10.0.0.1:3306/app"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("S3cr3tP4ss"), masked)
        assertFalse(masked.contains("hunter2pw"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
