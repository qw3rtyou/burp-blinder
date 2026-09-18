package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import net.portswigger.mcp.blinder.Blinder
import net.portswigger.mcp.blinder.SignatureDetector
import net.portswigger.mcp.blinder.ToolPolicy

/**
 * Blinder gateway decorator around the MCP SDK's [Server.addTool]. This is the single choke point
 * (identified in _workspace/01_analyst_tool-surface.md §4) through which every mcpTool / mcpUnitTool
 * / mcpPaginatedTool overload registers. Wrapping here — not inside the upstream tool handlers —
 * keeps our changes isolated from upstream drift.
 *
 * The decorator enforces, in order:
 *   1. deny-by-default  — a tool not on the verified allow-list gets a refusal, never its output.
 *   2. input rehydration — send tools have their placeholder arguments restored to real values
 *      (signed requests are skipped, not corrupted).
 *   3. output masking    — read tools have their response text masked before it reaches the agent.
 *
 * send_http1_request / send_http2_request are dual and receive both (2) and (3).
 */
fun Server.addGatewayTool(
    name: String,
    description: String,
    inputSchema: ToolSchema,
    handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult
) {
    val wrapped: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { connection, request ->
        val gateway = Blinder.gateway
        when {
            !gateway.isAllowed(name) -> CallToolResult(
                content = listOf(TextContent(gateway.denyMessage)),
                isError = true
            )

            else -> {
                val effectiveRequest =
                    if (ToolPolicy.needsInputRehydration(name)) rehydrateRequest(name, request) else request
                val result = handler(connection, effectiveRequest)
                if (ToolPolicy.needsOutputMasking(name)) maskResult(name, result) else result
            }
        }
    }
    addTool(name = name, description = description, inputSchema = inputSchema, handler = wrapped)
}

private fun rehydrateRequest(name: String, request: CallToolRequest): CallToolRequest {
    val args = request.params.arguments ?: return request
    val gateway = Blinder.gateway

    // One signature check over the whole request; v1 skips signed requests rather than resign.
    val combined = args.values.joinToString("\n") { flatten(it) }
    if (SignatureDetector.isSigned(combined)) {
        gateway.rehydrateInput(name, combined) // logs the skip via the gateway
        return request
    }

    val newArgs = JsonObject(args.mapValues { (_, value) -> rehydrateElement(value) })
    return CallToolRequest(request.params.copy(arguments = newArgs))
}

private fun rehydrateElement(element: JsonElement): JsonElement = when (element) {
    is JsonPrimitive ->
        if (element.isString) JsonPrimitive(Blinder.gateway.rehydrateValue(element.content)) else element

    is JsonObject -> JsonObject(element.mapValues { (_, v) -> rehydrateElement(v) })
    is JsonArray -> JsonArray(element.map { rehydrateElement(it) })
}

private fun flatten(element: JsonElement): String = when (element) {
    is JsonPrimitive -> element.content
    is JsonObject -> element.values.joinToString("\n") { flatten(it) }
    is JsonArray -> element.joinToString("\n") { flatten(it) }
}

private fun maskResult(name: String, result: CallToolResult): CallToolResult =
    result.copy(content = maskContentBlocks(name, result.content))

/**
 * Mask a read tool's content blocks. Only TextContent can be masking-verified; any other block
 * type (structuredContent, ImageContent, EmbeddedResource, ...) is withheld rather than passed
 * through unmasked (LEAK-3: deny-by-default for content whose masking we cannot vouch for). A short
 * notice is substituted so the agent knows content was withheld, without leaking it.
 */
internal fun maskContentBlocks(name: String, content: List<ContentBlock>): List<ContentBlock> {
    val gateway = Blinder.gateway
    val out = ArrayList<ContentBlock>(content.size)
    var withheld = 0
    for (block in content) {
        if (block is TextContent) out += TextContent(gateway.maskOutput(name, block.text)) else withheld++
    }
    if (withheld > 0) {
        gateway.onNonTextContentWithheld(name, withheld)
        out += TextContent("[Blinder withheld $withheld non-text content block(s): not masking-verified (deny-by-default)]")
    }
    return out
}
