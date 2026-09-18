package net.portswigger.mcp.blinder

/**
 * Process-wide holder for the single shared [Gateway] instance. The MCP tool wrappers
 * (McpTool.addGatewayTool) and the Montoya HttpHandler both read this holder so they share one
 * vault / dynamic-token namespace. ExtensionBase.initialize installs the real, logging-wired
 * instance; a default no-op-logging instance keeps unit tests and any pre-init call safe.
 */
object Blinder {
    @Volatile
    var gateway: Gateway = Gateway()
}
