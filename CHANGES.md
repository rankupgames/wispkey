# Changes

## 0.3.0 (2026-07-08)

### Multi-instance access

- Added host-managed instance enrollment for ephemeral VMs and workers with `wispkey instance enroll <name>`, one-time 48-character secrets, Argon2id-hashed instance secrets at rest, and scope selectors for partitions, projects, credentials, and tags.
- Added instance lifecycle and escalation commands: `instance list`, `show`, `scope add`, `scope remove`, `revoke`, `requests`, `approve`, and `deny`.
- Added schema v7 tables for `instances`, `instance_scopes`, and `access_requests`.
- Added repeatable proxy listeners with `wispkey serve --listen <spec>` for TCP, Unix domain sockets, and feature-gated Linux vsock. The default `wispkey serve` loopback TCP behavior remains unchanged.
- Added per-request instance authentication with `x-wispkey-instance-id` and `x-wispkey-instance-secret`. UDS and vsock listeners require identity by default; TCP listeners do not unless `--require-identity` is set.
- Added instance scope enforcement at token injection. Out-of-scope use returns HTTP 403 `out_of_scope`, queues an idempotent pending access request, and requires host approval before retry.
- Added public multi-instance deployment documentation in `docs/multi-instance-deployment.md` and updated the security model for authenticated, scoped, untrusted instance clients.

## 0.2.0 (2026-07-07)

### Project scoping and proxy hardening

- `src/core/schema.rs` and `src/core/mod.rs`: migrated vault schema to v6 and made credential names unique per project instead of vault-wide. Name-based credential operations now resolve within the active project or the explicit project scope used by the caller.
- `src/main.rs`: `wispkey add --value` now warns on stderr about shell-history and process-list exposure; `--value-file <path>` and `--value-file -` are the preferred non-interactive secret input paths.
- `src/policy/mod.rs`: agent-scoped policies now fail closed when the requester agent identity is unavailable, which is the proxy's current state because it has no trusted agent identity source.
- `src/proxy/mod.rs`: reverse-proxy mode now substitutes wisp tokens in the `X-Target-Url` query string before forwarding upstream.
- `src/proxy/management.rs`: `GET`/`DELETE /api/credentials/{name}` and `DELETE /api/partitions/{name}` honor the `?project=` scope.
- `src/core/schema.rs` and `src/migrate/mod.rs`: `vault.db` and generated `.env.wispkey` files are written with owner-only permissions on Unix.
- `src/proxy/mod.rs`: management token checks use constant-time comparison for both the management-token header and bearer-token form.

### Session hardening follow-up

- `src/core/session.rs` and `src/core/session_store.rs`: replaced the default raw base64 session key file with a private `SessionStore` abstraction and v2 machine-bound encrypted session payloads. Legacy plaintext sessions remain readable for migration and are rewritten as v2 after a successful load.
- `src/cli/status.rs`: reports the configured session-at-rest protection backend as `session_protection` in JSON output and `Protection` in text output.
- `README.md` and ignored local `_docs/*` planning docs: updated the session boundary language to state the new machine-bound behavior and its remaining same-user limitations.

### Audit log surfaces

- `src/audit/mod.rs` and `src/cli/log.rs`: merge vault-backed SQLite audit rows with vault-less `sideload-audit.jsonl` fallback rows, including `--credential`/`--since` filtering, exact-midnight UTC filtering, and JSON `source` markers.
- `tests/env_sideload.rs`: verifies `wispkey log --format json --credential openai` can read a vault-less `SideloadUsed` fallback event without exposing the sideloaded env secret.

### Correctness fixes

- `src/proxy/tokens.rs`: replaced token-by-token global `String::replace` with a single left-to-right replacement pass. The resolver now accepts the longest valid known token prefix inside a broad `wk_*` match, so a real token adjacent to lowercase or underscore text resolves instead of being over-matched.
- `src/proxy/tokens.rs`: preserves explicit env-sideload policy denials when a vault is unlocked instead of collapsing them into a later token-not-found error.
- `src/proxy/mod.rs`: strips `transfer-encoding` when recalculating `content-length` for buffered forwarded requests.
- `src/audit/mod.rs` and `src/secure_files.rs`: added owner-only fallback JSONL audit logging for env-sideload proxy use when no unlocked vault database is available.
- `src/proxy/tokens.rs`: records env-sideload policy denials to the vault audit DB when available, or to the fallback JSONL sink otherwise.
- `src/policy/mod.rs`: prunes expired rate-limit entries across buckets and evicts empty stale buckets during rate-limit evaluation.

### Regression tests

- `tests/proxy.rs`: added coverage for valid tokens followed immediately by lowercase/underscore text.
- `tests/proxy.rs`: added coverage proving inserted secret values are not rescanned and corrupted when they contain another wisp token string.
- `src/proxy/tests.rs`: added coverage that forwarded headers cannot keep both `transfer-encoding` and a recomputed `content-length`.
- `tests/env_sideload.rs`: added coverage that vault-less env sideload proxy use writes an audit row without logging the raw secret.
- `tests/env_sideload.rs`: added coverage that env-sideload policy denials with an unlocked vault return the policy denial rather than a misleading token-not-found error.

### Documentation

- `README.md`: updated the category wording to "credential firewall for AI agents", documented fallback sideload audit behavior, added a concise comparison section, and linked the internal threat model.

### Verification

- `cargo fmt -- --check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings -W clippy::suspicious -W clippy::style -W clippy::perf -W clippy::complexity`
- `git diff --check`

## 0.1.0

- Initial local-first WispKey CLI release with encrypted vault storage, wisp tokens, HTTP proxy mode, MCP tools, partitions, policies, audit logging, and encrypted bundle import/export.
