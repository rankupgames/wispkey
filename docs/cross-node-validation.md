# Cross-node validation evidence

This is the repeatable validation map for [#32](https://github.com/rankupgames/wispkey/issues/32).
The runtime is implemented; automated fixture results do not establish acceptance
for a particular live destination. Keep the issue open until the destination
owner records the remaining evidence below. WIA rollout execution, Android, and
EKS deployment are separate workstreams.

## Recorded local run: 2026-09-26

Validated against baseline `d406530` plus this validation change, using Rust
1.96.0 on Windows and WSL Ubuntu. The working tree's existing lockfile update
(`chacha20` 0.10.2) was retained for these runs.

| Check | Result |
| --- | --- |
| Windows `cargo test --all-features` | 371 passed, zero failures, two harness/service tests ignored as expected. The subsequently added live TLS rejection test passed separately. |
| Linux `cargo test --locked --all-features --lib operation` | 53 passed, zero failures, three harness/service tests ignored as expected. The final TLS test and strengthened helper output check passed in subsequent focused runs. |
| Linux PostgreSQL container fixture | Passed TLS rotation, old-password rejection, retained data, and server-log canary checks; fixture cleanup completed. |
| Windows and Linux `cargo clippy --all-targets --all-features -- -D warnings` | Passed. |
| `cargo fmt --all -- --check` and `git diff --check` | Passed. |

The isolated parent tests execute the ignored runtime/helper child tests. The
PostgreSQL script executes its ignored test separately. No macOS or live
destination acceptance run was performed in this session.

PR preparation on 2026-09-28 also reran the focused operation suite with the
unchanged committed lockfile (`chacha20` 0.10.1): Windows passed 49 tests with
two expected ignored harness/service tests; Linux passed 54 with three expected
ignored tests. This excludes the unrelated local lockfile update from the PR.
The macOS child permits only CoreFoundation's numeric encoding metadata, which
the OS initializes after launch; all inherited application variables remain
forbidden. See Apple's [encoding initialization](https://github.com/apple-oss-distributions/CF/blob/main/CFStringEncodings.c).

## Repeatable checks

Run from the repository root with a supported Rust toolchain:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

For focused cross-node checks:

```console
cargo test --all-features --lib operation
cargo test --all-features --test operations --test operation_auth --test instance_policy_identity
```

On Linux with Docker, also run:

```console
bash tests/support/postgres_operation_fixture.sh
```

The PostgreSQL command creates and removes a digest-pinned disposable container
bound to loopback. It uses only synthetic passwords, verifies old-password
rejection and a fresh new-password login, checks a retained application row, and
scans server logs for the selected and failure canaries. An ordinary `cargo test`
skips this external-service test. Do not run all ignored tests directly: the
runtime and helper child tests require their parent harnesses, which run them
automatically with isolated inputs.

The helper executes children only on Unix; Windows test results alone cannot
validate its stdin, process environment, output suppression, or process-group
termination. CI runs the regular suite on Linux, macOS, and Windows, and the
PostgreSQL fixture on Linux.

## Automated coverage

| Requirement | Evidence in the repository | Boundary of that evidence |
| --- | --- | --- |
| Exact requester and scope | `operation_auth`, `instance_policy_identity`, catalog tests, and `every_scope_field_is_checked_at_reservation_and_release` reject forged identity and changed operation, destination, environment, credential, project, catalog, or requester. | Catalog revision binds workload/consumer fields; the operator must attest that the catalog names the intended workload. |
| Bounded lifetime | `earliest_scope_session_or_requested_expiry_bounds_grant_and_attempt` checks the earliest deadline in grant, attempt, and persisted audit, plus expired-session denial. Existing tests cover expired/replaced grants and sessions. | No infinite session authorizes cross-node execution. |
| One use and concurrency | `concurrent_reservations_allow_only_one_attempt_per_grant_or_target` races separate SQLite connections for the same grant and for different operations on one target. Exactly one attempt and one `started` audit survive. Existing tests cover replay, cancellation, reconciliation, and audit-write failure. | Unknown remote outcomes remain consumed and require owner reconciliation. |
| Rotation and revocation | Grant tests bind selected, provider, and previous-password revisions; changing an instance-secret generation invalidates an in-flight attempt for both old and new requester authentication. The PostgreSQL fixture verifies actual old-password rejection. | Invalidating a grant or token does not revoke a plaintext value already delivered to an issuer or consumer. |
| Verified destination before selected-value release | The live SSH fixture rejects a mismatched host key. `untrusted_live_tls_peer_receives_no_http_or_selected_credential` rejects another CA during a real TLS handshake. `live_object_replacement_denies_before_selected_release` rejects replaced namespace and Secret UIDs. | Loopback SSH/TLS peers are controlled fixtures, not a deployed SSH host or Kubernetes API server. |
| Signed environment scope | `posture_scope_drift_never_releases_either_credential` covers endpoint, CA, cluster, context, environment, namespace/Secret UID, owner, consumer, issuer, encryption revision, and signer changes. `invalid_signed_posture_never_releases_either_credential` covers expired, future, overlong, missing, malformed-scope, and invalid-signature evidence. | Evidence is an owner attestation. WispKey does not discover effective RBAC or encryption-at-rest configuration. |
| Delivery and cleanup outcomes | Two synthetic environments, repeat delivery, revision changes, altered acknowledgements, lost acknowledgements, and key-only cleanup are exercised by the HTTPS fixtures. Cleanup preserves other keys and never releases the selected value; its result is `revocation_unverified`. | A Secret write acknowledgement is not proof of application reload or issuer revocation. |
| Private delivery and output | `stdin_only_child_keeps_canaries_out_of_output_and_store` runs a real Unix child that checks its argv, cleared inherited environment, and exact stdin; it emits received bytes in chunks and base64 before exiting 42. The parent verifies safe status and scans helper fixture files, including its replay database. SSH/runtime/API fixtures also check canary suppression. | This proves the tested helper channels; privileged destination code can retain plaintext and must be reviewed separately. |
| Audit and vault isolation | Tests enforce the exact eight-field audit and immutable credential reference, reject release when the start audit cannot commit, and preserve audit while excluding grants/attempts from backups. Runtime fixtures use a disposable vault and send only the selected value through the helper protocol. | These are application-level checks, not host-level forensic proof against a compromised runner or destination root. |

## Destination-owner acceptance still required

Use [operation-runtime.md](operation-runtime.md),
[restricted-helper.md](restricted-helper.md), and
[postgres-issuer.md](postgres-issuer.md) for setup and operator commands. Before
claiming live acceptance, record the owner, reviewed commit/version, destination
identity, operation, immutable credential reference, environment, and expiry.
Use synthetic credentials and a disposable workload first.

1. Verify the enrolled requester and fixed target independently. Install and
   review the restricted SSH account/helper policy, or the exact Kubernetes
   namespace/Secret and issuer function. Keep vault, session, master password,
   and posture signing key within their documented trust boundaries.
2. For Kubernetes, prove the provider can GET only the named namespace and
   GET/UPDATE only the precreated Secret. Exercise cross-environment denial and
   excessive-permission detection in the operator's posture review. Verify
   encryption at rest and audit/logging behavior before signing fresh posture.
3. Exercise approval, delivery, cancellation, expiry, requester revocation,
   credential rotation, replay, and an unreachable destination. Observe safe
   status and the eight-field audit. Reconcile uncertain results after checking
   the destination; do not automatically retry them.
4. Inspect process arguments/environment, local and remote files, service logs,
   management responses, and exported audit for synthetic values and their
   encoded forms. Record only pass/fail and metadata, never raw secret-bearing
   captures. Confirm no vault or unlock material reached the destination.
5. Prove the actual consumer reloads the newly delivered value, retains its
   application data, and rejects the old value at the issuer. Account for
   existing database sessions. Verify separately authorized cleanup after the
   original delivery grant expires; Secret removal alone is not revocation.

Store a sanitized evidence record containing version, platform, fixture or
destination identifiers, checks run, pass/fail, fixed outcome, and outstanding
limitations. No live-destination result or production rollout is implied by
this document.
