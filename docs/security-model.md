# WispKey Security Model

WispKey is a credential firewall for AI agents. Its main boundary is between a prompt-injectable agent process and plaintext credentials. Agents receive opaque `wk_*` tokens; WispKey substitutes approved tokens for real credentials at the proxy boundary and keeps plaintext secrets out of normal agent-visible CLI and MCP outputs.

## Defended Cases

- Prompt-injected or compromised agents reading plaintext credentials through normal WispKey CLI or MCP surfaces. `wispkey_get_token` returns wisp tokens, not raw values.
- Agents accidentally or intentionally sending vault-backed credentials before the proxy boundary. The proxy replaces valid wisp tokens in headers, supported text bodies, and URL query parameters.
- Credential use outside configured boundaries when host restrictions or TOML policies are configured. Policies can restrict hosts, paths, methods, time windows, and rate limits.
- Untrusted VM or worker instances using credentials outside their enrolled scope when served over identity-required transports. Instance requests must authenticate with an enrollment secret, scope checks fail closed, and out-of-scope use is denied before forwarding.
- VM fleet first-contact enrollment. Bootstrap tokens are scoped, optional-TTL-limited, optional-use-limited, revocable bearer tokens stored only as Argon2id hashes. The join endpoint is authenticated only by the bootstrap token and returns a per-instance identity.
- Silent privilege escalation by enrolled instances. Out-of-scope use creates a pending access request that must be approved by the host before the instance can retry successfully.
- Revocation racing an in-flight instance authentication. WispKey conditionally commits successful Argon2 verification only if the instance is still active, so a concurrent revoke fails the request closed.
- Brittle instance-secret rollout. Due-aware rotation atomically installs a new secret and can retain the previous hash for a bounded grace window. Successful authentication with the new secret clears the previous hash early.
- Silent vault-backed credential use. WispKey writes use and denial events to the SQLite audit log. Env-sideload-only proxy use without an unlocked vault writes fallback JSONL audit events.
- Audit token disclosure. New audit records store only an HMAC-SHA-256 fingerprint of a wisp token for correlation within each audit sink. The HMAC key stays in vault-only metadata or an owner-only local key file. Audit queries and exports redact token-like values from free-text fields and do not return reusable token capabilities or the fingerprint key.
- Owner-approved plaintext egress. `wispkey exec` records `CredentialExec` audit events when it injects a credential into a child process through stdin, a child-only environment variable, or askpass. `wispkey run` records `CredentialRun` events for manifest-based child environment injection, and `wispkey inject` records `CredentialInject` events for template rendering.
- Accidental env-sideload disclosure. `WISPKEY_SIDELOAD_<SLUG>` values are exposed to agents as deterministic `wk_env_<slug>` tokens; the raw env value is not printed or logged.
- Timing disclosure of proxy management tokens through direct string comparison. Management API tokens are compared in constant time.
- CA private keys used for `wispkey_issue_cert`. The MCP tool decrypts the CA material in-process, signs a generated keypair or CSR, and returns only the leaf certificate and (when generated) the leaf private key. Env-sideload values cannot be used as CA material.
- Agent-visible website-login generation. `wispkey login generate` and `wispkey_generate_login` create a unique password with the OS CSPRNG, store username and password together in encrypted credential material, and return only non-secret metadata. CLI `add` and MCP `wispkey_set` cannot create `website_login` credentials.

## Explicit Limits

- HTTPS CONNECT is a blind TCP tunnel. WispKey cannot substitute tokens inside CONNECT traffic. Use reverse proxy mode with `X-Target-Url` when HTTPS requests need token substitution.
- Default loopback TCP clients are trusted by design for backward compatibility. Explicit non-loopback TCP listeners require instance identity by default; `--no-require-identity` is an intentional override that prints a warning.
- Instance identities are bearer credentials. Protect `x-wispkey-instance-id` and `x-wispkey-instance-secret` in the VM environment or metadata channel. Rotate with `wispkey instance rotate-secret`; treat its one-time output like enrollment output.
- A compromised instance can use credentials that are already in its scope. Scope limits reduce blast radius; they do not make an in-scope credential safe after the instance is compromised.
- Transport security for untrusted instances depends on the channel. Bind UDS listeners to host-only socket paths, keep socket permissions tight, and use vsock only for the intended host/guest boundary. Instance authentication does not encrypt TCP; use an SSH tunnel or another authenticated encrypted host-only channel for cross-machine access. Do not expose identity-required listeners on networks where the instance secret can be intercepted.
- WispKey instance secrets and vault encryption use high-entropy symmetric material, but that does not make a classical SSH key exchange post-quantum. Cross-machine tunnels must negotiate a hybrid post-quantum key exchange such as ML-KEM/X25519 or NTRU Prime/X25519 when store-now-decrypt-later protection is required.
- WispKey does not defend against a same-OS-user local process that can read all local WispKey files, read the device seed, reconstruct machine inputs, call local OS APIs available to that user, attach a debugger, or inspect process memory.
- Root, Administrator, kernel-level compromise, malware with equivalent local privileges, or a malicious WispKey binary are out of scope.
- Body substitution is limited to text-like content types such as JSON, text, form-urlencoded, and XML. Binary or opaque body rewriting is intentionally not supported.
- Website-login browser fill and native-messaging handoff are not in this slice. Generated logins are saved before any fill attempt so a failed signup cannot strand an unknown password. Review dates never auto-delete credentials.
- Secrets are no longer protected by WispKey after they are intentionally sent upstream. The upstream service, SDKs, logs, and process memory are outside WispKey's boundary.
- `wispkey exec`, `wispkey run`, and `wispkey inject` are deliberate plaintext-egress paths for owner-run non-HTTP tools, similar in trust level to `op run` or `aws-vault exec`. A compromised owner shell can still run these commands or use the child process or rendered file to misuse the credential.
- `wispkey_issue_cert` is a deliberate MCP plaintext-egress path for a newly generated leaf private key, not for the CA. A caller that can invoke the tool receives the leaf identity and can use it until the certificate expires or is revoked by an external process. WispKey does not currently revoke issued leaves.
- Plaintext secrets stored in external client configuration, shell startup files, or MCP `env` blocks are outside the vault. Prefer process environment forwarding or an OS credential manager when available.
- Fallback JSONL audit files created by releases before token fingerprinting can contain reusable `wk_*` values. Keep those owner-only files private and remove or archive them through a protected channel after upgrading.

## Session Boundary

The default unlocked session file is machine-bound and encrypted. WispKey derives a local wrapping key from an owner-only device seed, machine identity inputs, and the OS username, then encrypts the session payload.

This prevents a simple read of `~/.wispkey/session` from recovering the vault key. It is not a same-user security boundary. A same-user process with broad local file access or memory inspection can still recover or use unlocked credentials.

`wispkey unlock --remember` stores the derived vault key (never the master password) in the platform credential store when available: macOS Keychain or Windows Credential Manager. Linux and other hosts fall back to a machine-bound `session-protector` file with its own timeout so WispKey stays free of D-Bus/libsecret build dependencies. `wispkey lock` revokes the short-lived session; `wispkey lock --forget` also deletes the protector. Headless callers should use `--password-file` rather than a CLI password argument. See [`docs/headless-unlock.md`](headless-unlock.md) for recovery and the Boring Computer smoke-test sequence.

`WISPKEY_SESSION_PLAINTEXT=1` writes the legacy plaintext session format for explicit debugging or rollback. It is not the default and is reported as plaintext protection in `wispkey --format json status`.

## Owner IPC And Tray Boundary

The optional tray is a desktop extension of the CLI, not a second credential store. `wispkey tray` serves an owner-only local endpoint; `wispkey-tray` talks to that endpoint from a native webview. There is no unauthenticated localhost HTTP form.

On Unix the endpoint is `owner.sock` under the vault directory, mode `0600`, with same-UID `SO_PEERCRED` checks. On Windows it is a per-user named pipe. The `owner.json` discovery file stores pid, protocol version, and endpoint only.

Secrets in IPC requests are resolved in-process and never returned in responses, written to tracing logs, put on argv, or shown in notifications. Known secret JSON fields are redacted before log formatting. List and add responses include names, types, tags, hosts, wisp tokens, and project/partition metadata only.

Compound OVH API saves insert three `api_key` credentials in one transaction. Any empty field, duplicate name, or insert failure rolls back all three. A locked vault, unauthorized peer, missing endpoint, or malformed request fails closed. `wispkey lock` clears the session file and the in-memory master key.

Closing a tray dialog must not stop the background process. Quit or the `shutdown` IPC method stops it. Start-at-login writes a user autostart desktop file on Linux; it does not change permissions on `~/.config/autostart`.

The tray does not add a same-OS-user security boundary. A process running as the vault owner can still attach to the socket, inspect memory, or read local files.

## Exec, Run, And Inject Boundary

`wispkey exec` exists for non-HTTP consumers that cannot use the token-substituting proxy. It requires an unlocked vault session, resolves the credential inside the WispKey process, and injects the value only into the child through selected channels:

- `--stdin` writes one secret line to child stdin and closes it.
- `--env <VAR>` sets `VAR=<secret>` only on the child `Command`.
- `--askpass` configures `SUDO_ASKPASS`, `SSH_ASKPASS`, and `GIT_ASKPASS` to an internal helper. `SSH_ASKPASS_REQUIRE=force` is set for SSH askpass flows, and sudo commands should use `sudo -A`.

The askpass channel uses a per-exec owner-only handoff capability file. `exec --askpass` writes a small handoff under WispKey's private vault directory and passes the path to the spawned child as `WISPKEY_ASKPASS_HANDOFF`. The hidden helper reads and consumes that handoff, resolves only the named credential for that launch, and refuses to run without a valid handoff. The removed `WISPKEY_ASKPASS_CRED` environment path is not supported, so `wispkey askpass` is no longer a standalone plaintext oracle.

The plaintext value must not transit child argv, parent environment variables other than child-only askpass handoff metadata, WispKey stdout/stderr, tracing logs, or audit fields. Audit rows store the credential name, child program name only, channel summary, project, and exit status. They do not store the value or full child argument list.

`wispkey run` uses the same unlocked-vault resolution boundary for `[env]` manifest entries. Values of the form `cred:<name>` are resolved in-process and set only through `Command::env` on the child. Plain string manifest values are passed through unchanged. Run audit rows store credential names, the child program name only, project, and exit status.

`wispkey inject` renders `{{ cred:<name> }}` template references in-process. File output uses WispKey's owner-only writer, which is 0600 on Unix and restricted with Windows ACLs where available. `--stdout` is an explicit plaintext disclosure to the caller. Inject audit rows store credential names, the output destination path or `stdout`, and project.

## Agent-Scoped Policies

Agent-scoped policies fail closed when the requester agent identity is unavailable. The proxy currently has no trusted agent identity source, so a policy with an `agent = "..."` scope applies to proxy requests even when no agent name is known.

## Instance Boundary

Multi-instance access adds an authenticated untrusted-client boundary for ephemeral VMs and worker instances. Each instance enrolls on the host with a unique id and one-time secret. The secret is Argon2id-hashed at rest and must be presented on every proxied request with `x-wispkey-instance-id` and `x-wispkey-instance-secret`.

Fleet self-enrollment uses bootstrap tokens for first contact. A host mints a bootstrap token with partition, project, credential, or tag scopes plus optional TTL and use limits. The plaintext bootstrap token is shown once, stored only as an Argon2id hash, and can be revoked. Redemption is atomic/race-safe, so max-use limits are strictly enforced under concurrent joins. `POST /api/instances/join` intentionally does not require a management token or existing instance identity; possession of a valid bootstrap token is the authenticator for that endpoint. On success, WispKey returns a new instance id and one-time instance secret, then future proxy requests must use that per-instance identity.

Unix domain socket, Linux AF_VSOCK, Firecracker UDS-backed vsock, and non-loopback TCP listeners require instance identity by default. Loopback TCP keeps the original no-identity default unless `--require-identity` is set. Missing, invalid, or revoked instance identity returns HTTP 401.

After authentication, WispKey checks instance scope before injecting a vault credential. Scope selectors can match by partition, project, credential name, or exact tag, but credential selectors and approved requests persist and compare the resolved credential ID. A same-named credential in another project does not inherit that authorization. If a vault token is out of scope, WispKey returns HTTP 403 with `error: "out_of_scope"`, queues or reuses a pending access request, audits the denial, and does not forward the upstream request. Host approval makes only that credential ID available to the instance on retry. Env-sideload tokens have no persisted credential ID, so identity-authenticated requests cannot use or request approval for them.

Each instance secret is 48 uniformly generated mixed-alphanumeric characters, approximately 286 bits of entropy, and only an Argon2id hash is stored. `instance rotate-secret` supports `--if-older-than` for idempotent periodic jobs and `--grace` for rollout overlap. A request authenticated with the new secret clears the previous secret immediately; otherwise the previous hash expires at the recorded deadline. Revocation and rotation races use conditional active-state/hash updates and fail closed.
