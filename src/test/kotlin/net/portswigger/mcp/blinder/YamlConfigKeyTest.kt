package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-11: generalise key-based masking to the `key: value` delimiter family (YAML / .properties /
 * config), sharing the sensitive-key logic. Value only is masked; key/separator/quotes/indent are
 * preserved; masking only fires for sensitive keys (never `name: foo`).
 */
class YamlConfigKeyTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `yaml sensitive values are masked`() {
        assertTrue(mask("password: Sup3rY4mlP4ss").contains("password: {{SECRET_1}}"))
        assertTrue(mask("  api_secret: sk_abc123").contains("  api_secret: {{SECRET_1}}"))
        assertTrue(mask("DB_PASSWORD: prodpw").contains("DB_PASSWORD: {{SECRET_1}}"))
        val quoted = mask("""token: "q-token-val"""")
        assertFalse(quoted.contains("q-token-val"), quoted)
        assertTrue(quoted.contains("""token: "{{SECRET_1}}""""), quoted)
    }

    @Test
    fun `non-sensitive yaml keys are not masked`() {
        for (line in listOf("name: myapp", "title: hello world", "replicas: 3", "host: a.com:8080", "url: http://a.com/path")) {
            val out = mask(line)
            assertEquals(line, out, "over-masked: $out")
        }
    }

    @Test
    fun `env and form key=value still masked (regression)`() {
        assertTrue(mask("PASSWORD=envpass").contains("PASSWORD={{SECRET_1}}"))
        assertTrue(mask("""{"DB_PASSWORD":"x"}""").contains("{{SECRET_1|j}}"))
    }

    @Test
    fun `yaml masking round-trips with indent and quotes preserved`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = "db:\n  password: Sup3rY4mlP4ss\n  name: prod\napi_secret: 'sk_x1y2z3'\n"
        val masked = masker.mask(real)
        assertFalse(masked.contains("Sup3rY4mlP4ss"), masked)
        assertFalse(masked.contains("sk_x1y2z3"), masked)
        assertTrue(masked.contains("  name: prod"), masked) // non-sensitive preserved
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
