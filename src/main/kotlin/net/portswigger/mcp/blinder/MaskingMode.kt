package net.portswigger.mcp.blinder

/**
 * Gateway masking policy, selectable at runtime from the MCP config tab.
 *
 *  - [OFF]: read output passes through unmasked and send input is not rehydrated (vault unused).
 *    The deny-by-default TOOL policy still applies — unregistered tools remain blocked.
 *  - [SELECTIVE]: default. Detected secrets/PII are masked; everything else is left readable.
 *  - [STRICT]: aggressive masking — IP/UUID/MAC always masked (ignoring their toggles), recognised
 *    sensitive containers (Authorization/Cookie/Set-Cookie) masked shape-agnostically, and the
 *    high-entropy floor is lowered. Over-masking is accepted in exchange for maximum secrecy.
 */
enum class MaskingMode {
    OFF,
    SELECTIVE,
    STRICT;

    companion object {
        fun fromNameOrDefault(name: String?): MaskingMode =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: SELECTIVE
    }
}
