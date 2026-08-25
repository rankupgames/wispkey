# Changes

## Unreleased

### PKI-aware certificate issuance

- Added the `wispkey_issue_cert` MCP tool so a CA private key can stay in the vault while agents request leaf identities. The tool either generates an EC P-256/P-384 or RSA 2048/4096 keypair or signs a PEM CSR.
- The CA credential must be PEM. A bundled CA certificate is preferred; `ca_cert` supplies the issuer certificate when the credential is key-only. Issuance fails closed unless the certificate is a currently valid CA with certificate-signing key usage when that extension is present, and the requested leaf lifetime cannot extend past the CA expiration.
- Returned material is the leaf certificate PEM and, for generated keys, the leaf private key PEM. The CA private key is never included in the MCP response, audit log, or error text.
- Successful issuance writes a `CertificateIssued` audit event with the CA credential name, leaf CN, SAN/key/validity/serial metadata, and project. Audit rows do not store PEM or key material.
- Leaf certificates are X.509 v3 end-entity certs with Digital Signature plus RSA Key Encipherment or EC Key Agreement, and Extended Key Usage for TLS server and client authentication.

### Cross-machine and Firecracker instance access

- Added `firecracker-vsock:/absolute/base.sock:<port>` listeners for Firecracker's actual guest-to-host transport. WispKey binds Firecracker's required `<base>_<port>` Unix socket while preserving the existing feature-gated `vsock://<cid>:<port>` listener for Linux environments that expose host AF_VSOCK directly.
- Non-loopback TCP listeners now require instance identity by default. The legacy `wispkey serve` loopback listener remains unchanged, and an explicit `--no-require-identity` override on non-loopback TCP prints a warning.
- Added an operating-system-neutral TCP integration test for missing, invalid, scoped, out-of-scope, approved, and revoked instance identities so the flow can run natively on Windows as well as Linux and macOS.
- Documented SSH-tunneled TCP as the encrypted cross-machine path for Windows and other servers; per-instance authentication is not transport encryption.
- Closed a revocation time-of-check/time-of-use race: successful Argon2 verification now updates `last_seen_at` only while the instance is still active, so a revoke that lands during password hashing makes the in-flight authentication fail closed.
- Added due-aware `instance rotate-secret` automation. Rotation atomically replaces the 48-character CSPRNG bearer secret, can skip secrets younger than `--if-older-than`, and keeps the previous secret for a bounded `--grace` window. The first successful use of the new secret retires the previous one early.
- Migrated vaults to schema v9 with secret-rotation timestamps and bounded previous-secret metadata. Secret hashes remain Argon2id-protected; plaintext rotation output is shown only once.
- Migrated vaults to schema v10 so credential selectors and access requests persist the exact credential ID. Unambiguous legacy name-only rows are backfilled; ambiguous same-name rows remain unbound and fail closed.
- Denied env-sideload tokens for identity-authenticated instance requests because sideloads have no persisted credential ID that can be enrolled or approved.
- Documented fail-closed hybrid post-quantum SSH key exchange for cross-machine tunnels. Instance-secret rotation limits exposure time but does not substitute for quantum-resistant transport key exchange.

## 0.4.0 (2026-07-08)

### Secret injection for subprocesses

- Added `wispkey exec --credential <name> [--project <p>] [--stdin] [--env <VAR>] [--askpass] -- <command> [args...]` for audited subprocess secret injection outside the HTTP proxy.
- Added `wispkey run [--manifest <path>] [--project <p>] -- <command> [args...]` for manifest-based multi-secret child environment injection. Manifests use `[env]` entries where `cred:<name>` resolves a credential and plain strings pass through literally.
- Added `wispkey inject -i <infile|-> [-o <outfile>] [--project <p>] [--stdout]` for rendering `{{ cred:<name> }}` template references to owner-only output files, with explicit `--stdout` for caller-visible plaintext.
- Added the hidden internal `wispkey askpass` helper for `SUDO_ASKPASS`, `SSH_ASKPASS`, and `GIT_ASKPASS` flows. `exec --askpass` now creates a per-exec owner-only handoff capability file exposed to the child with `WISPKEY_ASKPASS_HANDOFF`; the helper refuses to run without a valid handoff and is not a standalone plaintext oracle.
- `exec`, `run`, and `inject` resolve credentials within the active or explicit project, fail closed when the vault is locked or a referenced credential is missing, and never interpolate secrets into child argv, parent environment, WispKey stdout/stderr except explicit `inject --stdout`, tracing logs, or audit value fields.
- Added `CredentialExec`, `CredentialRun`, and `CredentialInject` audit events containing credential names, command or output metadata, project, and exit status where applicable, with no plaintext secret values.
- Documented `exec`, `run`, and `inject` usage, security boundaries, and the stdin/stdout limitations for intentional plaintext egress.
- Added integration tests for exec env, stdin, askpass, missing credential, missing channel, run manifest injection, inject rendering, owner-only output files, fail-closed behavior, and audit behavior.

### Instance bootstrap tokens

- Added schema v8 `bootstrap_tokens` storage with Argon2id-hashed bootstrap token material, scope JSON, optional TTL, optional max-use count, use count, and revocation status. The v7-to-v8 migration is additive and preserves existing credential, instance, scope, and access-request rows.
- Added `wispkey instance bootstrap create/list/revoke` for host-minted scoped bootstrap tokens and `wispkey instance join [<bootstrap-token>] [--token-file <path|->] --name <instance-name>` for local self-enrollment tests and host-side automation. Positional bootstrap tokens still work but warn about argv exposure; examples prefer `--token-file -`.
- Added unauthenticated first-contact `POST /api/instances/join` on the proxy management API. The endpoint is authenticated only by the bootstrap token, remains reachable on identity-required listeners, returns a new per-instance id and one-time secret on success, and emits `InstanceJoined` audit events without logging bootstrap tokens or instance secrets.
- Bootstrap redemption is atomic/race-safe, fails closed for invalid, expired, exhausted, and revoked tokens, strictly enforces max-use counts under concurrent joins, and copies the bootstrap token's partition/project/credential/tag selectors onto the new instance.
- Added unit and integration tests for single-use redemption, copied tag scope, expired/revoked failures, additive v7-to-v8 migration, and the Unix-socket join endpoint path that requires sockets.

### Audit export and streaming

- Added `wispkey audit export [--since <ts>] [--until <ts>] [--credential <name>] [--encoding jsonl|json] [-o <file>]` for bulk SIEM egress from the combined vault-backed and sideload-fallback audit sinks.
- Added `wispkey audit tail [--follow] [--credential <name>]` to print newest audit events as JSONL and optionally poll for new events with a forward `(timestamp,id)` cursor that does not skip same-timestamp rows, for piping into tools such as `logger`, Vector, or Fluent Bit.
- Extended audit queries with unbounded range export while preserving the existing `wispkey log --last` behavior.
- Added integration tests for JSONL export, JSON file export, date-range filtering, tail output, and absence of plaintext secret values in audit export output.

### Fixes

- Stored-timestamp parsing now accepts both RFC 3339 and the SQLite space-separated `YYYY-MM-DD HH:MM:SS[.f]` form (assumed UTC). A single row written through raw SQL or `CURRENT_TIMESTAMP` previously made `list`, `mcp` listing, and other reads fail with `Conversion error from type Text at index: 8, premature end of input`; one legacy row can no longer break a whole listing.

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
- `tests/env_sideload.rs`: verifies `wispkey --format json log --credential openai` can read a vault-less `SideloadUsed` fallback event without exposing the sideloaded env secret.

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
