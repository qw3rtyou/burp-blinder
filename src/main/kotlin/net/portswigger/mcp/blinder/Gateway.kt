package net.portswigger.mcp.blinder

/**
 * The single shared gateway. One instance owns the vault and the dynamic-token store and is shared
 * by the MCP tool wrappers (McpTool.addGatewayTool) and the Montoya HttpHandler
 * (BlinderHttpHandler), so a placeholder the masker shows the agent is exactly the placeholder the
 * rehydrator/egress net consumes.
 *
 * Pure Kotlin (no Montoya, no MCP SDK types) so the whole gateway is headless-unit-testable.
 * Logging is injected as a plain lambda.
 */
class Gateway(
    private val log: (String) -> Unit = {},
    dynamicExtractorRules: List<DynamicTokenExtractor.Rule> = emptyList(),
    /** LEAK-2 policy toggle (default OFF). When on, IPv4/IPv6 addresses are masked in read output. */
    maskIpAddresses: Boolean = false,
    /** Policy toggle (default OFF). When on, UUID identifiers are masked in read output. */
    maskUuids: Boolean = false
) {
    val vault = Vault()
    val dynamicTokens = DynamicTokenStore()
    private val masker = Masker(vault, maskIpAddresses, maskUuids)
    private val rehydrator = Rehydrator(vault, dynamicTokens)
    private val extractor = DynamicTokenExtractor(dynamicTokens, dynamicExtractorRules)

    // ---- Deny-by-default -------------------------------------------------------------------

    val denyMessage: String =
        "Blinder gateway: tool is not on the verified allow-list and is denied (deny-by-default)."

    fun isAllowed(tool: String): Boolean = ToolPolicy.isAllowed(tool)

    // ---- Read-side masking (MCP output) ----------------------------------------------------

    /** Mask a read tool's output text; other tools' text is returned unchanged. */
    fun maskOutput(tool: String, text: String): String =
        if (ToolPolicy.needsOutputMasking(tool)) masker.mask(text) else text

    /**
     * Report that a read tool returned content blocks that are not maskable text and were withheld
     * (LEAK-3 hardening: unverified content is not exposed on the agent channel).
     */
    fun onNonTextContentWithheld(tool: String, count: Int) {
        log("Blinder: withheld $count non-text content block(s) from read tool '$tool' (not masking-verified - deny-by-default)")
    }

    // ---- Send-side rehydration (MCP input) -------------------------------------------------

    data class InputOutcome(
        val text: String,
        val signatureSkipped: Boolean,
        val residual: List<String>
    )

    /**
     * Rehydrate a send tool's input string. Signed requests (HMAC/SigV4/OAuth) are skipped and
     * logged rather than corrupted — v1 does not resign. Non-send tools return the text unchanged.
     */
    /** Plain per-field rehydration (no policy/signature gating; the caller has already gated). */
    fun rehydrateValue(text: String): String = rehydrator.rehydrateText(text)

    fun rehydrateInput(tool: String, text: String): InputOutcome {
        if (!ToolPolicy.needsInputRehydration(tool)) return InputOutcome(text, false, emptyList())
        if (SignatureDetector.isSigned(text)) {
            log("Blinder: '$tool' looks like a signed request - skipping rehydration (unsupported in v1)")
            return InputOutcome(text, true, emptyList())
        }
        val result = rehydrator.rehydrate(text)
        if (result.hasResidual) {
            log("Blinder: '$tool' has unresolved placeholders after rehydration: ${result.residual}")
        }
        return InputOutcome(result.text, false, result.residual)
    }

    // ---- Montoya egress safety net + dynamic token capture ---------------------------------

    /** Final egress substitution for outbound requests (Repeater/Intruder/Editor manual fires). */
    fun rehydrateEgress(rawRequest: String): InputOutcome {
        if (SignatureDetector.isSigned(rawRequest)) {
            log("Blinder egress: signed request detected - skipping rehydration (unsupported in v1)")
            return InputOutcome(rawRequest, true, emptyList())
        }
        val result = rehydrator.rehydrate(rawRequest)
        return InputOutcome(result.text, false, result.residual)
    }

    /** Observe a live response and capture dynamic tokens (CSRF/nonce) into the store. */
    fun captureResponse(rawResponse: String) {
        val captured = extractor.observe(rawResponse)
        if (captured.isNotEmpty()) log("Blinder: captured dynamic tokens: $captured")
    }

    fun clearSession() {
        vault.clear()
        dynamicTokens.clear()
    }
}
