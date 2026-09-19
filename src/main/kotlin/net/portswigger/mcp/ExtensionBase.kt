package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.blinder.Blinder
import net.portswigger.mcp.blinder.Gateway
import net.portswigger.mcp.blinder.montoya.BlinderHttpHandler
import net.portswigger.mcp.blinder.montoya.SwingRevealApprover
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())

        // Install the shared Blinder gateway before the MCP server registers tools, so the tool
        // wrappers (McpTool.addGatewayTool) and the traffic hook below share one vault namespace.
        val gateway = Gateway(
            log = { message -> api.logging().logToOutput(message) },
            maskIpAddresses = config.maskIpAddresses,
            maskUuids = config.maskUuids,
            maskingMode = config.maskingMode,
            revealApprover = SwingRevealApprover()
        )
        Blinder.gateway = gateway
        val httpHandlerRegistration = api.http().registerHttpHandler(
            BlinderHttpHandler(gateway) { message -> api.logging().logToOutput(message) }
        )

        val serverManager = KtorServerManager(api)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        configUi.onMaskingModeChanged { mode -> gateway.maskingMode = mode }

        api.userInterface().registerSuiteTab("MCP", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            configUi.cleanup()
            config.cleanup()
            httpHandlerRegistration.deregister()
            gateway.clearSession()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }
}