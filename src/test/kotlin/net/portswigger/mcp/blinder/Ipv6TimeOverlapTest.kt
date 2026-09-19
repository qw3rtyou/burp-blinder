package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * LOW-1 (#18): an IPv6 address whose leading groups look like a clock time (e.g. 2001:12:34:56::1)
 * must be fully masked, not partially skipped by the time-preservation carve-out. Real clock times
 * (Date headers, standalone) must still be preserved.
 */
class Ipv6TimeOverlapTest {

    private fun strict() = Vault().let { it to Masker(it, mode = MaskingMode.STRICT) }

    @Test
    fun `ipv6 with time-shaped groups is fully masked (single placeholder) and round-trips`() {
        for (addr in listOf("2001:12:34:56::1", "2001:db8::12:34:56", "fe80::10:30:45")) {
            val (vault, masker) = strict()
            val rehydrator = Rehydrator(vault)
            val real = "peer=$addr;"
            val masked = masker.mask(real)
            assertFalse(masked.contains(addr), "IPv6 partially leaked: $masked")
            assertEquals("peer={{IP_1}};", masked, "expected one whole IP placeholder: $masked")
            assertEquals(real, rehydrator.rehydrate(masked).text)
        }
    }

    @Test
    fun `full 8-group and compressed loopback ipv6 still masked (regression)`() {
        val (v1, m1) = strict()
        assertTrue(m1.mask("a 2001:0db8:85a3:0000:0000:8a2e:0370:7334 b").contains("{{IP_1}}"))
        val (v2, m2) = strict()
        assertTrue(m2.mask("loopback ::1 here").contains("{{IP_1}}"))
    }

    @Test
    fun `clock times are preserved (no ipv6 false positive)`() {
        val (_, m) = strict()
        val out = m.mask("Date: Mon, 15 Jan 2024 10:30:45 GMT")
        assertTrue(out.contains("10:30:45"), out)
        assertFalse(out.contains("{{IP"), out)

        val (_, m2) = strict()
        val out2 = m2.mask("started at 23:59:59 today")
        assertTrue(out2.contains("23:59:59"), out2)
        assertFalse(out2.contains("{{IP"), out2)
    }

    @Test
    fun `ipv4 still masked (regression)`() {
        val (_, m) = strict()
        val out = m.mask("X-Real-IP: 203.0.113.45")
        assertFalse(out.contains("203.0.113.45"), out)
        assertTrue(out.contains("{{IP_1}}"), out)
    }
}
