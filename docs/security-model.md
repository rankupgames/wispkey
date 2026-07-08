# WispKey Security Model

WispKey is a credential firewall for AI agents. Its main boundary is between a prompt-injectable agent process and plaintext credentials. Agents receive opaque `wk_*` tokens; WispKey substitutes approved tokens for real credentials at the proxy boundary and keeps plaintext secrets out of normal agent-visible CLI and MCP outputs.

## Defended Cases

- Prompt-injected or compromised agents reading plaintext credentials through normal WispKey CLI or MCP surfaces. `wispkey_get_token` returns wisp tokens, not raw values.
- Agents accidentally or intentionally sending vault-backed credentials before the proxy boundary. The proxy replaces valid wisp tokens in headers, supported text bodies, and URL query parameters.
- Credential use outside configured boundaries when host restrictions or TOML policies are configured. Policies can restrict hosts, paths, methods, time windows, and rate limits.
- Silent vault-backed credential use. WispKey writes use and denial events to the SQLite audit log. Env-sideload-only proxy use without an unlocked vault writes fallback JSONL audit events.
- Accidental env-sideload disclosure. `WISPKEY_SIDELOAD_<SLUG>` values are exposed to agents as deterministic `wk_env_<slug>` tokens; the raw env value is not printed or logged.
- Timing disclosure of proxy management tokens through direct string comparison. Management API tokens are compared in constant time.

## Explicit Limits

- HTTPS CONNECT is a blind TCP tunnel. WispKey cannot substitute tokens inside CONNECT traffic. Use reverse proxy mode with `X-Target-Url` when HTTPS requests need token substitution.
- Localhost clients are trusted by design. Keep the proxy bound to loopback and run it only on trusted machines.
- WispKey does not defend against a same-OS-user local process that can read all local WispKey files, read the device seed, reconstruct machine inputs, call local OS APIs available to that user, attach a debugger, or inspect process memory.
- Root, Administrator, kernel-level compromise, malware with equivalent local privileges, or a malicious WispKey binary are out of scope.
- Body substitution is limited to text-like content types such as JSON, text, form-urlencoded, and XML. Binary or opaque body rewriting is intentionally not supported.
- Secrets are no longer protected by WispKey after they are intentionally sent upstream. The upstream service, SDKs, logs, and process memory are outside WispKey's boundary.
- Plaintext secrets stored in external client configuration, shell startup files, or MCP `env` blocks are outside the vault. Prefer process environment forwarding or an OS credential manager when available.

## Session Boundary

The default unlocked session file is machine-bound and encrypted. WispKey derives a local wrapping key from an owner-only device seed, machine identity inputs, and the OS username, then encrypts the session payload.

This prevents a simple read of `~/.wispkey/session` from recovering the vault key. It is not a same-user security boundary. A same-user process with broad local file access or memory inspection can still recover or use unlocked credentials.

`WISPKEY_SESSION_PLAINTEXT=1` writes the legacy plaintext session format for explicit debugging or rollback. It is not the default and is reported as plaintext protection in `wispkey status --format json`.

## Agent-Scoped Policies

Agent-scoped policies fail closed when the requester agent identity is unavailable. The proxy currently has no trusted agent identity source, so a policy with an `agent = "..."` scope applies to proxy requests even when no agent name is known.
