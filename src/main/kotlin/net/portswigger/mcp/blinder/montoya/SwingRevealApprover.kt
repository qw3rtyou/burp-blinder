package net.portswigger.mcp.blinder.montoya

import net.portswigger.mcp.blinder.RevealApprover
import net.portswigger.mcp.blinder.RevealDecision
import net.portswigger.mcp.security.findBurpFrame
import java.awt.GraphicsEnvironment
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JOptionPane
import javax.swing.SwingUtilities

/**
 * Montoya/Swing implementation of [RevealApprover]. Shows a modal Burp dialog on the EDT and blocks
 * the calling (MCP handler) thread on a latch until the human decides or the timeout elapses. The
 * real value is NEVER shown in the prompt — only the placeholder, a type label and the length — so a
 * screen-shoulder or a mis-click cannot leak it before the decision.
 *
 * Fail-closed: headless (no UI) or timeout returns DENY.
 */
class SwingRevealApprover(
    private val timeoutMs: Long = 120_000L
) : RevealApprover {

    override fun requestReveal(placeholder: String, typeLabel: String, valueLength: Int): RevealDecision {
        if (GraphicsEnvironment.isHeadless()) return RevealDecision.DENY

        val latch = CountDownLatch(1)
        val result = AtomicReference(RevealDecision.DENY)

        SwingUtilities.invokeLater {
            try {
                val message = buildString {
                    appendLine("An AI agent is requesting the REAL value behind a masked placeholder.")
                    appendLine()
                    appendLine("Placeholder: $placeholder")
                    appendLine("Type: $typeLabel")
                    appendLine("Length: $valueLength characters")
                    appendLine()
                    appendLine("The real value is NOT shown here and will only be disclosed to the agent")
                    appendLine("if you approve.")
                }
                val options = arrayOf<Any>("Allow Once", "Always Allow This Value", "Deny")
                val choice = JOptionPane.showOptionDialog(
                    findBurpFrame(),
                    message,
                    "Blinder — reveal request",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,
                    options,
                    options[2] // default highlight = Deny
                )
                result.set(
                    when (choice) {
                        0 -> RevealDecision.ALLOW_ONCE
                        1 -> RevealDecision.ALLOW_ALWAYS
                        else -> RevealDecision.DENY
                    }
                )
            } finally {
                latch.countDown()
            }
        }

        return if (latch.await(timeoutMs, TimeUnit.MILLISECONDS)) result.get() else RevealDecision.DENY
    }
}
