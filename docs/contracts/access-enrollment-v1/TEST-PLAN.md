# Adversarial and setup plan — draft 2

This plan is a release gate list, not a claim that runtime behavior exists.
Everything uses generated disposable fixtures. Never run against a real vault,
production Clerk, Cloudflare resources, live grants or personal OS key entries.

## Delivered pure checks

| Contract invariant | Executable coverage |
|---|---|
| Disabled until explicitly enabled | Default `Context.enabled` and enrollment default gate |
| All scopes and keys bound | Each endpoint/account/vault/project/partition and device/recipient/auth/root/epoch/policy field mutated |
| Separate rights | All 16 subsets of four rights against all four requested rights |
| Unknown classification restricted | Null, empty, unknown, case mismatch and higher classes never replicate |
| Sign-in is insufficient | Missing identity proof, owner grant, approval state, local unlock or plugin consent denied |
| Independent plugin boundary | Device approval alone insufficient; only separately authorized metadata/request; hosted kind rejected |
| Lifecycle/freshness | Exact deadline, not-yet-valid, stale nonce/binding, missing signed head, dispatch deadline, delayed reply, replay, restart, clock uncertainty/rollback, excessive budget |
| Last-moment changes | Re-evaluation after revocation, lock, cancel, ring/revision change, lease expiry |
| Enrollment substitution | Altered request ID, nonce, keys, account, scope, description, rights or expiry rejected |
| Enrollment race/replay | Both cancel/approve serializations, repeated approve, terminal-state revival, stale CAS revision |
| Snapshot integrity prerequisites | Signature/hash/decrypted scope/head each independently required |
| Replay/rollback/downgrade | Lower sequence, same sequence/different hash, unsupported envelope/payload version |
| Idempotency | Exact same verified current head returns checkpoint unchanged |
| Rotation/recovery | New key/root/epoch and restored context cannot reuse old authority |
| Redaction | Fixed-category exception excludes synthetic sensitive input |
| Legacy compatibility | Old project/partition/share/account-only route inputs denied |

Run `python3 -B -m unittest discover -s docs/contracts/access-enrollment-v1 -v`.
Expected: 22 methods, 52 decision vectors and 19 freshness-response vectors, plus enumerated subcases. Under one
second on the inspected host. Test count is not a cryptographic assurance measure.

## Required before runtime integration

| Suite | Setup and adversarial cases | Acceptance evidence |
|---|---|---|
| Wire/crypto interoperability | Disposable Rust age sender/receiver and independent reference age implementation; exact approved Ed25519 signed-byte vectors verified in Rust and Cloud runtime; RFC/library vectors plus generated fixture keys | Valid round trips; wrong recipient/root/key/signature/purpose/context, byte flips, missing final chunk, wrong hash/size, unknown suite/version, duplicate JSON keys, malformed base64, integer overflow, oversized/compressed payloads rejected before import; no secret printed |
| Pairing UX/proofs | Two independent synthetic devices, hostile relay fixture, separate account fixtures | Full transcript comparison; both key-possession proofs; substituted QR/key/account/request, relay to different endpoint, wrong issuer, self-approval and expired presence rejected; abort creates no ciphertext/grant; no OAuth-device-flow claim |
| Database enrollment races | Two real database connections with barriers; no sleeps as synchronization | At most one approval for pending revision; cancel wins before approval or revokes winner; approver revoked concurrently cannot issue usable approval; unique nonce/request constraints; failure/rollback leaves no partial key grant |
| Authorization surface parity | CLI, MCP, proxy, browser handoff, operation executor, Cloud paths and owner recovery adapters | Same managed resource fixtures yield same scope/ring/revision/expiry denials at actual release; forged labels/headers/body flags, unregistered/sideload fallback, plugin through enrolled device, special owner-route flags cannot bypass |
| Legacy-route migration | Seed pre-policy Cloud schema, old binaries/clients and every route alias; activate managed namespace/floor in fixture | Account-only project/partition/share/list/manifest/payload/read/write/delete paths refuse managed data; old readers reject markers; old snapshots cannot lower floor after deletion of last managed row; no partial migration |
| Snapshot transactions | Two processes, mock relay immutable objects and local SQLite; inject failure after each staging step | Verify full payload before import; local concurrent edit/revoke/classification change blocks commit; payload+policy+checkpoint atomic; corrupt late row rolls back all; duplicate names/auth IDs/profile dependencies cannot cross scope |
| Freshness/adversarial server | Fake wall/monotonic clocks, delayed/suppressed/reordered responses, owner offline | Fresh challenge/head required, old valid head denied, nonce mismatch denied, exact deadline denied, no authority after restart/clock uncertainty; measured stale-authority bound matches approved budget |
| Rotation and revocation | Synthetic owner + secondary + replacement keys, in-flight old upload/download, retained old ciphertext | Old proof cannot authorize new epoch; partial rotation fails closed; signed transition cannot widen scope; revoked secondary excluded from future ciphertext; document old ciphertext still decrypts, and provider rotation is separate |
| Restore and loss | Backup/restore into empty synthetic vault, old signed checkpoint and account login only | Restored state disabled; no cached lease/consent/session accepted; latest policy head and fresh approval required; loss of all trusted keys reports unavailable recovery until reviewed recovery material exists |
| Storage and presence | Separate temporary OS credential namespace per supported platform; headless fixture | Missing/unavailable backend fails according to reviewed policy; no silent software fallback where hardware required; presence bound to exact request and actual signing; ACLs, backup exclusion and cleanup checked; no personal keychain entries |
| Metadata/redaction | Sentinel passwords, tokens, emails, descriptions, malformed upstream errors | Default discovery/status/errors/audit exclude sentinel values, raw keys/proofs/bodies and capabilities; scoped owner inventory exposes only approved public information |
| Setup and default-off | Fresh checkout, default build, experimental build, restart, configuration migration, backup restore | Default build has no enrollment or automated behavior; compiling feature alone gives no consent; unsupported configuration/version fails closed; all setup uses temporary `WISPKEY_VAULT_PATH`; clear teardown |
| Two-device end to end | Primary and secondary in separate temporary directories/OS users; fixture Cloud; explicit opted-in session | First enrollment/import, edits/deletion, mixed classifications, wrong account, simultaneous change, lock/logout, restart, missed hints, network outage and cancellation; no use rights gained; measured healthy-online propagation |

Keep actual provider execution, live approval, OS enrollment, production migration,
permission changes, deployment and billing out of these suites. Cargo regressions
should run later in the parent-coordinated build slot once runtime changes exist.
The existing cloud/auth-release/backup/browser/operation suites are integration
baselines, not evidence that this draft has been enforced on those surfaces.

## Self-review findings and dispositions

- **Exportability versus use rights:** clarified that possession defeats any
  software-only prohibition on external use; read-only is sync authority. This is
  a product/security decision, not a test that can make export revocable.
- **Freshness:** timestamps/monotonic counters alone cannot defeat a malicious
  frozen relay. Nonce-bound owner head now uses the original local challenge dispatch deadline,
  atomic one-use consumption and non-restored clock epoch; receipt cannot reset
  the budget. No measured stale-authority bound is claimed; the budget remains
  unapproved.
- **Second key possession:** an Ed25519 device signature does not prove possession
  of a distinct age recipient key. Pairing handshake is blocked on review of both
  proofs and out-of-band transcript comparison.
- **Legacy bypass:** existing account routes must all gate managed data. New
  routes alone are insufficient; schema/route enforcement remains unimplemented.
- **Principal/binding consistency:** self-review found that matching grant and
  caller principal also needs to equal the bound device for device grants. Added
  an explicit denial and regression before handoff.
- **Restore rollback:** a backup can undo locally stored high-water marks; restart
  and restore require a fresh pinned-owner head and approval, not only a stored
  sequence comparison. Baseline provisioning remains a runtime gate.
- **Concurrency:** pure CAS transition tests prove the chosen serial outcomes,
  not database isolation. Real two-connection and release-boundary tests are still
  mandatory. No claim of comprehensive race safety is made by this suite.

Parent review and cryptographic review have **not** occurred. Unresolved choices
are listed in the contract; no merge, PR, integration or deployment is implied.
