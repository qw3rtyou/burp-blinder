# burp-blinder

**A bidirectional tokenization gateway for the [Burp Suite MCP server](https://github.com/PortSwigger/mcp-server).**

When an AI agent drives Burp Suite over MCP, everything the agent reads — proxy
history, repeater responses, request/response bodies — normally flows verbatim to
the model. burp-blinder sits in that path: data the agent **reads** is masked to
placeholders, the real values are kept in an in-process vault, and they are
**re-injected before the request leaves Burp**. Requests still work; the model
never sees the real secrets.

```
                 read tools (history, responses)
   Burp  ──────────────────────────────────────▶  [ mask ]  ──▶  AI agent
    ▲                                                 │              (sees placeholders)
    │                                              [ vault ]
    │            send tools (repeater, egress)        │
    └──────────────────────────────────────────  [ rehydrate ]  ◀──┘
                                                                 (real values re-injected)
```

> ℹ️ **This is a modified fork.** burp-blinder is based on
> [`PortSwigger/mcp-server`](https://github.com/PortSwigger/mcp-server) and is
> distributed under the **GNU GPL-3.0** (see [Licence](#licence)). The blinder
> tokenization gateway (masking, vault, rehydration, dynamic-token capture, the
> human-gated reveal, and the deny-by-default tool decorator) was added on top of
> upstream in 2026. All upstream MCP-server functionality is preserved.

## Why

The goal is to make it safe to use a **capable external/frontier model** for Burp
traffic analysis without handing it your credentials, PII, or internal topology.
You keep frontier-model quality; secrets never leave your machine in cleartext.

- **Minimal-necessity:** structure is preserved (HTTP method, paths, header names,
  JSON keys, status lines) so the model can still reason about the traffic — only
  the *sensitive* parts are replaced.
- **Referential consistency:** the same real value always maps to the same
  placeholder, so relationships (e.g. a session reused across requests) survive
  masking and the agent can still spot IDOR-style patterns.
- **Human-gated disclosure:** the agent can request a real value via
  `reveal_placeholder`, but it is returned **only** after an explicit human
  approval in a Burp dialog — fail-closed and audit-logged.
- **Deny-by-default:** every MCP tool passes through a single decorator; a tool is
  only reachable if it has been classified (read → masked, send → rehydrated).

## What gets masked

Credentials (Cookie/Set-Cookie, Bearer/Basic, API-key headers, connection-string
passwords, PEM keys), shape-based secrets (JWT, `ghp_…`/`sk_live_…`/`xoxb-…`/AWS/…,
including secrets nested inside base64 / `data:` / percent-encoding), PII (emails,
phone numbers, Luhn-valid cards, SSN, IBAN, wallets), and sensitive keys in form /
JSON / query / YAML / XML / ADO.NET syntaxes. Identifiers (IP / UUID / MAC) are
mode-dependent.

**See [MASKING.md](MASKING.md) for the full, current list, the masking modes, and
the scope / limitations.**

### Masking modes (`MCP` tab dropdown, switchable at runtime)

| Mode | Behaviour |
|------|-----------|
| **OFF** | No masking — pass-through (rehydration is a no-op). |
| **SELECTIVE** (default) | Masks detected secrets and PII; leaves IP / UUID / MAC readable. |
| **STRICT** | Also masks IP / UUID / MAC; still preserves readable structure. |

## Architecture

The gateway core lives in `net.portswigger.mcp.blinder.*` and is **pure Kotlin with
no Montoya dependency**, so masking / vault / rehydration / detection are covered by
a headless test suite (277 tests). Montoya integration is isolated to
`blinder/montoya/BlinderHttpHandler.kt` + `ExtensionBase.kt`, and the MCP wiring to
a single deny-by-default decorator in `tools/GatewayTool.kt`.

## Installation

### Option A — download the release (no build)

Grab `burp-blinder-all.jar` from the [Releases](../../releases) page and load it in
Burp (see [Loading into Burp](#loading-the-extension-into-burp-suite)).

### Option B — build from source

**Prerequisites:** Java on your `PATH` (`java --version`) and the `jar` command
(`jar --version`).

```bash
git clone https://github.com/qw3rtyou/burp-blinder.git
cd burp-blinder
./gradlew embedProxyJar
```

The extension is built to `build/libs/burp-blinder-all.jar`.

Run the tests with `./gradlew test` (run `embedProxyJar` and `test` as separate
invocations).

### Loading the extension into Burp Suite

1. Open Burp Suite and go to the **Extensions** tab.
2. Click **Add**, set **Extension Type** to **Java**.
3. **Select file …** → choose `burp-blinder-all.jar` → **Next**.

## Configuration

Configure the extension in Burp's **MCP** tab:

- **Enabled** — toggles the MCP server.
- **Masking mode** — OFF / SELECTIVE / STRICT dropdown (switchable at runtime).
- **Enable tools that can edit your config** — exposes config-editing MCP tools.
- **Advanced** — server host/port. Default: `http://127.0.0.1:9876`.

### Connecting an MCP client

Point your MCP client at the SSE server:

```
http://127.0.0.1:9876
```

For clients that only support stdio (e.g. Claude Desktop), the extension ships a
packaged stdio proxy. Use the extension's installer to write the client config, or
configure it manually:

```json
{
  "mcpServers": {
    "burp": {
      "command": "<path to the Java executable packaged with Burp>",
      "args": [
        "-jar",
        "/path/to/proxy/jar/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```

Then restart the client (with Burp running and the extension loaded). The stdio
proxy source is at [PortSwigger/mcp-proxy](https://github.com/PortSwigger/mcp-proxy).

## Scope & limitations

burp-blinder targets the **external-model** case. For a fully-isolated local model
with no logging and no downstream tools its leak-prevention value is marginal (by
design). It does **not** mask source-code logic — you cannot hide logic and still
have the agent analyze it — only *incidental* secrets embedded in code. See the
[Scope section of MASKING.md](MASKING.md#scope--when-to-use) for the full picture,
and the project notes for residual items still pending real-environment validation
(HTTP/2 delayed-egress reconstruction, per-site dynamic-token tuning).

## Licence

burp-blinder is distributed under the **GNU General Public License v3.0**, the same
licence as its upstream. See [LICENSE](LICENSE).

- Upstream: [`PortSwigger/mcp-server`](https://github.com/PortSwigger/mcp-server)
  — © PortSwigger (Daniel S, Daniel Allen). All rights in the upstream code remain
  with the original authors.
- Modifications (the blinder gateway) © 2026 the burp-blinder contributors, added on
  top of upstream and released under GPL-3.0.

Because this is GPL-3.0 software, any distribution must keep the source available
and retain the GPL-3.0 licence.
