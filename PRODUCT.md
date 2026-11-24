<!-- impeccable:product-schema 1 -->
# WispKey

Platform: web (marketing site) and desktop (460px tray window, Svelte in a native shell).

Assumptions: inferred from the project brief, `AGENTS.md`, `docs/DESIGN.md`, the tray UI source and the wispkey-cloud landing page. No interview channel was available.

## What it is

A local-first credential firewall for AI agents. Secrets live in a local encrypted vault. Agents get opaque `wk_*` wisp tokens. The proxy and MCP server swap tokens for real values at the network boundary, subject to host scope, lifecycle and access rings. Only `routine` credentials are released by the proxy and MCP.

## Who uses it

Developers who run coding agents on their own machines and want to keep API keys out of agent context, prompts and `.env` files. Technical, security-aware, terminal-first.

## Surfaces

- Website: explains the mechanism and points to the open-source repository and the optional Cloud companion.
- Tray: unlock the vault, import `.env`/JSON/key files or the clipboard, add a credential, list credentials, copy or rotate tokens, start at login.

## Truth constraints

- Owner tools `exec`, `run`, `inject` and certificate issuance release plaintext by design. Never claim that agents can never see secrets.
- Blind CONNECT (`HTTPS_PROXY`) cannot swap tokens inside TLS. HTTPS substitution uses reverse-proxy mode with `X-Target-Url`.
- No certifications, customer logos, audits or usage numbers.
- Cloud sharing acceptance flows are not shipped.

## Brand

- Existing marks: key glyph in a rounded tile, violet accent `#6848D8`, Inter and JetBrains Mono.
- Selected aesthetic (2026-11-08): preserve the exact bold silkscreen concept—heavy cream serif, midnight indigo, ice-blue/coral ink, rough halftone vault and flat print shapes. Reduce the amount of information, not the style. Main headline: “Agents without Friction”. Earlier wolf/globe images remain aesthetic references only. No wolf logo.
- Usability and trust references only: Infisical, 1Password, Bitwarden, Doppler.
