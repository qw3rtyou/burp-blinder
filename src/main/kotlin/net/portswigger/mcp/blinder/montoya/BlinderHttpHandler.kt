package net.portswigger.mcp.blinder.montoya

import burp.api.montoya.core.Annotations
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import net.portswigger.mcp.blinder.Gateway
import net.portswigger.mcp.blinder.Placeholder

/**
 * Montoya HTTP handler: the single traffic-stream hook (registered in ExtensionBase.initialize).
 *
 * It serves two purposes identified in _workspace/01_analyst_montoya-hooks.md §3-1:
 *   1. Egress rehydration safety net — any outbound request that still carries a placeholder is
 *      rehydrated here. This is the only reliable net that also covers the DELAYED egress paths
 *      (Repeater / Intruder / editor) that the user fires manually, since those bypass the MCP
 *      input wrapper.
 *   2. Dynamic-token capture — every live response is observed so CSRF/nonce tokens land in the
 *      shared store for {{CSRF:auto}} injection on the next request.
 *
 * Loop safety: MCP send_http tool requests are already fully rehydrated at the tool boundary, so
 * they carry no placeholders and take the untouched fast path here. A request we do rehydrate is
 * tagged with an annotation note so a re-entry is skipped.
 */
class BlinderHttpHandler(
    private val gateway: Gateway,
    private val log: (String) -> Unit = {}
) : HttpHandler {

    private val processedNote = "blinder:rehydrated"

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        val raw = requestToBeSent.toString()

        if (!Placeholder.containsAny(raw)) {
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }
        if (requestToBeSent.annotations().notes()?.contains(processedNote) == true) {
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        val outcome = gateway.rehydrateEgress(raw)
        if (outcome.signatureSkipped) {
            log("Blinder HttpHandler: signed egress request left unmodified (v1 unsupported)")
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }
        if (outcome.residual.isNotEmpty()) {
            log("Blinder HttpHandler: egress request has unresolved placeholders: ${outcome.residual}")
        }

        val rebuilt: HttpRequest =
            HttpRequest.httpRequest(requestToBeSent.httpService(), outcome.text)
        val annotations: Annotations = requestToBeSent.annotations().withNotes(
            listOfNotNull(requestToBeSent.annotations().notes()?.takeIf { it.isNotBlank() }, processedNote)
                .joinToString("; ")
        )
        return RequestToBeSentAction.continueWith(rebuilt, annotations)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        // Observe only; never alter live responses. Masking happens at the MCP boundary.
        runCatching { gateway.captureResponse(responseReceived.toString()) }
            .onFailure { log("Blinder HttpHandler: token capture failed: ${it.message}") }
        return ResponseReceivedAction.continueWith(responseReceived)
    }
}
