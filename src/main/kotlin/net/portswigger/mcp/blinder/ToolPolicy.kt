package net.portswigger.mcp.blinder

/**
 * Deny-by-default tool policy, derived from the analyst tool-surface map
 * (_workspace/01_analyst_tool-surface.md). A tool is processed only if it is on one of these
 * verified lists; anything else (an upstream-added tool, a typo, a future tool) is denied.
 *
 * send_http1_request / send_http2_request are dual (send AND read): they egress agent input and
 * return the live response, so they appear in both the rehydrate and the mask sets.
 */
object ToolPolicy {

    /** Read tools whose output must be masked (11 read tools + the 2 dual send/read tools). */
    val OUTPUT_MASK_TOOLS: Set<String> = setOf(
        "get_proxy_http_history",
        "get_proxy_http_history_regex",
        "get_organizer_items",
        "get_organizer_items_regex",
        "get_proxy_websocket_history",
        "get_proxy_websocket_history_regex",
        "get_active_editor_contents",
        "output_project_options",
        "output_user_options",
        "get_scanner_issues",
        "get_collaborator_interactions",
        // dual send+read
        "send_http1_request",
        "send_http2_request"
    )

    /** Send/egress tools whose input placeholders must be rehydrated (6 tools). */
    val INPUT_REHYDRATE_TOOLS: Set<String> = setOf(
        "send_http1_request",
        "send_http2_request",
        "create_repeater_tab",
        "create_repeater_tab_http2",
        "send_to_intruder",
        "set_active_editor_contents"
    )

    /** Neutral tools: no sensitive data, passed through untouched (10 tools). */
    val NEUTRAL_TOOLS: Set<String> = setOf(
        "url_encode",
        "url_decode",
        "base64_encode",
        "base64_decode",
        "generate_random_string",
        "set_task_execution_engine_state",
        "set_proxy_intercept_state",
        "set_project_options",
        "set_user_options",
        "generate_collaborator_payload"
    )

    /** The full whitelist. Any tool not present is denied. */
    val ALLOWED: Set<String> = OUTPUT_MASK_TOOLS + INPUT_REHYDRATE_TOOLS + NEUTRAL_TOOLS

    fun isAllowed(tool: String): Boolean = tool in ALLOWED
    fun needsOutputMasking(tool: String): Boolean = tool in OUTPUT_MASK_TOOLS
    fun needsInputRehydration(tool: String): Boolean = tool in INPUT_REHYDRATE_TOOLS
}
