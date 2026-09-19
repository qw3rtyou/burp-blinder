package net.portswigger.mcp.config

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.blinder.MaskingMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class MaskingModeDefaultTest {

    // A fresh store (like real Burp: getString returns null for unset keys) yields the default.
    private fun freshConfig(): McpConfig {
        val backing = mutableMapOf<String, Any?>()
        val store = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { backing[firstArg()] as? Boolean }
            every { getString(any()) } answers { backing[firstArg()] as? String }
            every { getInteger(any()) } answers { backing[firstArg()] as? Int }
            every { setBoolean(any(), any()) } answers { backing[firstArg()] = secondArg<Boolean>() }
            every { setString(any(), any()) } answers { backing[firstArg()] = secondArg<String>() }
            every { setInteger(any(), any()) } answers { backing[firstArg()] = secondArg<Int>() }
        }
        val logging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }
        return McpConfig(store, logging)
    }

    @Test
    fun `default masking mode is STRICT (conceal-by-default)`() {
        assertEquals(MaskingMode.STRICT, freshConfig().maskingMode)
    }

    @Test
    fun `masking mode round-trips through config`() {
        val config = freshConfig()
        config.maskingMode = MaskingMode.SELECTIVE
        assertEquals(MaskingMode.SELECTIVE, config.maskingMode)
        config.maskingMode = MaskingMode.OFF
        assertEquals(MaskingMode.OFF, config.maskingMode)
    }
}
