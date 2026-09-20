# What burp-blinder masks

burp-blinder is a bidirectional tokenization gateway for the Burp MCP server.
Data the AI agent reads through MCP is masked to placeholders; the real values
are kept in an in-process vault and re-injected before requests leave Burp, so
requests still work while the agent never sees the real secrets.

This document lists what is currently detected and masked.

## Masking modes (`MCP` tab dropdown)

| Mode | Behaviour |
|------|-----------|
| **OFF** | No masking — traffic passes through unchanged (rehydration is a no-op). |
| **SELECTIVE** | Masks detected secrets and PII; leaves IP / UUID / MAC readable (usability first). |
| **STRICT** (recommended default) | Masks all data-shaped values including IP / UUID / MAC, while preserving readable structure (header names, JSON keys, URL paths, standard metadata). |

Placeholders are referentially consistent: the same real value always maps to the
same placeholder (regardless of encoding/context), so relationships (e.g. same
session across requests) survive masking.

## 1. Credentials / authentication
- **Authorization: Bearer** → `{{BEARER_n}}`
- **Authorization: Basic** → `{{BASIC_n}}`
- **Other Authorization schemes** (Token, ApiKey, …) → `{{SECRET_n}}`
- **API-key headers** (`X-Api-Key`, `Api-Key`, `X-Auth-Token`, …) → `{{APIKEY_n}}`
- **Cookie / Set-Cookie values** → `{{COOKIE_SESSION_n}}` / `{{COOKIE_n}}`
- **Connection-string passwords** (`postgres://user:****@host`, `jdbc:mysql://…`,
  redis/amqp/mongodb/ftp) → password masked, scheme/user/host/port/path preserved
- **PEM private keys / signature blocks** (`-----BEGIN … PRIVATE KEY-----`) → `{{PEM_n}}`

## 2. Tokens / secrets (shape-based)
- **JWT** — selective: structure, `alg` and claim keys preserved; sensitive claim
  values and the signature masked
- **High-entropy secrets** — GitHub `ghp_…`, Stripe `sk_live_…`/`whsec_…`,
  Slack `xoxb-…`, Google `AIza…`, AWS secret keys, SendGrid `SG.…`, npm tokens,
  Azure `AccountKey=…`, etc. → `{{SECRET_n}}`
- **Secrets inside nested encodings** — base64 / `data:` URIs / percent-encoding are
  decoded, the inner secret masked, then re-encoded (inner value never leaks)

## 3. PII
- **Emails** — plain and percent-encoded (`alice%40corp.com`) → `{{EMAIL_n}}` (format-preserving)
- **Phone numbers** — separator, country-code (`+81 …`) and parenthesized (`(212)555-0100`) forms → `{{PHONE_n}}`
- **Credit cards** — 13–19 digits, Luhn-validated → `{{CARD_n}}`
- **SSN** — `NNN-NN-NNNN` shape and key-based → `{{SSN_n}}`
- **IBAN, crypto wallets** → `{{SECRET_n}}`

## 4. Identifiers (mode-dependent)
| Value | SELECTIVE | STRICT / toggle |
|-------|-----------|-----------------|
| IPv4 / IPv6 | readable | masked `{{IP_n}}` |
| UUID | readable | masked `{{UUID_n}}` |
| MAC address | readable | masked `{{MAC_n}}` |

Toggles: `McpConfig.maskIpAddresses`, `maskUuids` (both default off; STRICT overrides).

## 5. Sensitive keys (form / JSON / query)
When a key name is sensitive (`password`, `passwd`, `pwd`, `token`, `access_token`,
`refresh_token`, `secret`, `api_key`, `auth`, `session`, `otp`, `pin`, …) its value
is masked — in form-urlencoded bodies, JSON, and query strings.

## Human-gated disclosure
`reveal_placeholder` returns a placeholder's real value **only after explicit human
approval** in a Burp dialog (Allow once / Allow this value always / Deny). It is
fail-closed (default deny, deny on timeout/headless/error) and audit-logged.

## Structure preserved (never masked)
HTTP method / path structure / status line, header names, JSON keys, URL path
segments, standard non-sensitive header values (Content-Type, Server, Date incl.
the clock), and the Burp response envelope.

## Not masked (current scope)
Names, street addresses, postal codes, geo-coordinates; passports / driver-licence
and other national IDs beyond SSN; pure-alphabetic word-like secrets (detection
limit — use STRICT + reveal). These can be extended if needed.

## Scope & when to use
burp-blinder makes it safe to use an **external / frontier AI** for Burp traffic
analysis: you get frontier-model quality while PII, keys and internal identifiers
are stripped from what the model sees.

- **Best fit:** external model + traffic carrying PII / keys / internal topology (the common case).
- **Fully-isolated local model** (no logging, no downstream tools): leak-prevention value is
  marginal — that is expected; blinder targets the external-model case. It can still add
  defense-in-depth when the "local" model is on shared infra, logs prompts, or the agent calls
  external tools.
- **Source-code IP is out of scope.** You cannot mask logic and still have the agent analyze it.
  For code-touching analysis that must not leave the org, run a local model and send only the
  minimal relevant code. burp-blinder only strips *incidental* secrets embedded in code
  (hardcoded keys, internal URLs/hosts).
