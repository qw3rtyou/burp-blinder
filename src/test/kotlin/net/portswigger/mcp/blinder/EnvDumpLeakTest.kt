package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-10 env/config-dump leaks: (1) connection-string passwords with an empty username
 * (`scheme://:pass@`), and (2) prefixed/suffixed secret keys (DB_PASSWORD, API_SECRET, ...).
 */
class EnvDumpLeakTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `empty-username connection-string password is masked`() {
        for (uri in listOf("redis://:cachepass@cache.example.com:6379/0", "amqp://:pw12345@rabbit.example.com:5672/v")) {
            val out = mask("""{"url":"$uri"}""")
            assertFalse(out.contains("cachepass") || out.contains("pw12345"), out)
            assertTrue(out.contains("://:{{SECRET_1}}@"), out) // empty user preserved, password masked
        }
    }

    @Test
    fun `user-password connection string still works (regression)`() {
        val out = mask("db=postgres://admin:S3cr3tP4ss@db.example.com:5432/prod")
        assertTrue(out.contains("postgres://admin:{{SECRET_1}}@db.example.com:5432/prod"), out)
    }

    @Test
    fun `prefixed and suffixed secret keys are masked (json)`() {
        val cases = listOf(
            """{"DB_PASSWORD":"Pr0dDbP4ss!"}""" to "Pr0dDbP4ss!",
            """{"MYSQL_ROOT_PASSWORD":"rootpw"}""" to "rootpw",
            """{"db_pass":"dbp"}""" to "dbp",
            """{"API_SECRET":"sk_abc123"}""" to "sk_abc123",
            """{"ACCESS_TOKEN":"at_xyz789"}""" to "at_xyz789",
            """{"AWS_ACCESS_KEY":"AKIAEXAMPLE"}""" to "AKIAEXAMPLE"
        )
        for ((json, secret) in cases) {
            val out = mask(json)
            assertFalse(out.contains(secret), "leaked: $out")
            assertTrue(out.contains("{{"), "not masked: $out")
        }
    }

    @Test
    fun `similar-but-non-secret keys are not masked (no false positives)`() {
        // NB: `username` is no longer here — it now masks as PII (see EscapedHistoryCookieLeakTest).
        val out = mask("""{"bypass":"true","compass":"north","public_key":"pk-abc","keyboard":"qwerty"}""")
        assertTrue(out.contains("\"bypass\":\"true\""), out)
        assertTrue(out.contains("\"compass\":\"north\""), out)
        assertTrue(out.contains("\"public_key\":\"pk-abc\""), out)
        assertTrue(out.contains("\"keyboard\":\"qwerty\""), out)
        assertFalse(out.contains("{{"), out)
    }

    @Test
    fun `prefixed key masking round-trips`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = """{"DB_PASSWORD":"Pr0dDbP4ss!","url":"redis://:cachepass@cache.example.com:6379"}"""
        val masked = masker.mask(real)
        assertFalse(masked.contains("Pr0dDbP4ss!"), masked)
        assertFalse(masked.contains("cachepass"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
