# Access rings and trusted-device enrollment — draft 1

**Status: proposed for parent/owner review; not an approved or implemented protocol.**
Contract identifier: `wispkey-access-enrollment/draft-1`. Related issues:
[WispKey #49](https://github.com/rankupgames/wispkey/issues/49),
[Cloud #5](https://github.com/rankupgames/wispkey-cloud/issues/5), and
[sync #48](https://github.com/rankupgames/wispkey/issues/48).

This directory contains a policy/state-machine model and synthetic decision
vectors. It adds no runtime modules, dependencies, schema, commands, network
routes, keys or grants. Nothing imports the model from the product. Model entry
points default to disabled. Explicit test fixtures enable evaluation only.
Passing these tests does not validate cryptography, approve defaults, implement
enrollment, or finish either issue. No PR is authorized before parent review.

## Evidence and reuse

Inspected WispKey base `1d147e0` and Cloud source `525203e1263ac4e1df41ff7d8ce7d2135a31cf7c`.
The Cloud checkout also contained separate hosting work; this draft does not edit it.

| Existing source | Relevant boundary |
|---|---|
| [`src/core/crypto.rs`](../../../src/core/crypto.rs), [`docs/cloud-sync.md`](../../cloud-sync.md) | Local AES-GCM encryption and Argon2id/AES-GCM shared-passphrase `WKCS` transport do not provide per-device narrow authority. |
| [`docs/auth-registry.md`](../../auth-registry.md), [`src/core/auth.rs`](../../../src/core/auth.rs) | Portable auth identity/revision, terminal revocation, finite delegated deadlines, exact origin and authenticated downgrade markers must survive replication. |
| [`src/operations/environment.rs`](../../../src/operations/environment.rs) | Existing Ed25519 verification uses `ring::signature::ED25519`, verifies exact decoded bytes before parsing and bounds inputs. Reuse the library pattern, not its unrelated key or signing purpose. |
| [`Cargo.lock`](../../../Cargo.lock) | `ring` is pinned to 0.17.14. There is no `age` dependency or device-enrollment protocol to reuse as a finished implementation. |
| [`docs/realtime-sync-coordinator.md`](../../realtime-sync-coordinator.md), [`docs/foreground-sync-watch.md`](../../foreground-sync-watch.md) | `Admission::Ready` is trusted adapter output, not proof. Watch is manual owner/shared-passphrase sync, not trusted-device enrollment. |
| [Cloud middleware](https://github.com/rankupgames/wispkey-cloud/blob/525203e1263ac4e1df41ff7d8ce7d2135a31cf7c/src/middleware/auth.ts), [routes](https://github.com/rankupgames/wispkey-cloud/blob/525203e1263ac4e1df41ff7d8ce7d2135a31cf7c/src/index.ts) | Clerk account authentication and account-owned project/partition/share routes currently lack this device policy. Account authentication is necessary but insufficient. |

The [age specification v1.1.0](https://c2sp.org/age@v1.1.0) defines X25519
recipients and fresh per-file keys. The candidate is an unmodified age format
through an established [Rust age library](https://docs.rs/age/latest/age/),
**not** a new X25519/HKDF/AEAD construction. No version has been selected or added.
X25519 encryption does not establish the sender's identity; an owner signature
must bind the ciphertext and authorization context. See the
[age author's authentication discussion](https://words.filippo.io/age-authentication/).
Source review establishes suitability to investigate, not security approval of
this composition. Native hardware-key and post-quantum alternatives exist in the
specification; neither is implicitly selected by this draft.

## Proposed first slice and threat boundary

One primary owner device exports one **dedicated, explicitly routine and
exportable partition** to one approved secondary. The primary alone publishes;
the secondary cannot write, merge, enroll other devices, approve itself, rotate
owner trust, grant plugins, or raise protection permissions. No multi-writer,
organization sharing, new credential execution, or hosted executor is in this
slice. Each future recipient requires its own reviewed grant and ciphertext.

The dedicated partition is an explicit export consent boundary. Every included
row and dependent bundle/profile must be inventoried and classified by the owner.
Unknown rows, non-exportable entries, dangling dependencies, or restricted/critical
entries block the entire snapshot; silently filtering could break bundle semantics.
Do not include unrelated signup profiles, notes, audit history, sessions, instance
secrets, bootstrap tokens, whole-vault master keys, existing sync passphrases, or a
reusable partition key. Coordinate versioned auth/profile payloads with signup
work before integrating; this draft does not allocate their schema version.

**Exportable means the recipient can ultimately copy plaintext.** Read-only means
read-only synchronization authority, not read-only upstream API rights. A recipient
holding plaintext can act outside WispKey, retain old snapshots or share it. A
`use` denial below constrains compliant WispKey mediated operations only. This
slice is unsuitable if the owner needs secrets to remain non-exportable or later
revocation to erase copied data. Moving a formerly routine item to critical cannot
undo prior disclosure; rotate/revoke it at the provider when necessary.

Cloud transports ciphertext and bounded metadata; it receives no private key,
vault key, passphrase, or plaintext. A hostile Cloud can withhold or delete data,
observe routing/size/timing, or replay old signed objects. Signatures alone do not
establish freshness. A compromised owner or approved export recipient is outside
the confidentiality guarantee for its authorized plaintext. Local same-user code
can already access an unlocked owner vault. Hosted credential execution would put
plaintext in a new operator boundary and requires separate explicit opt-in,
architecture, threat review and tests; it is never `kind=device` by convenience.

## Authorization contract

Candidate ring names are `routine`, `restricted`, `critical`. Missing/unrecognized
classification becomes restricted. Unsupported *policy versions* are denied, not
mapped to a permissive default. Ring labels never authenticate a caller.

| Right | Meaning | First-slice ceiling |
|---|---|---|
| `discover` | Minimal owner-authorized alias/status metadata | Exact device or separately consented plugin grant; no tokens, usernames, notes or secret-dependent hashes |
| `replicate` | Receive and decrypt a bounded export snapshot | Approved device only; entire dedicated partition explicitly routine/exportable |
| `request` | Submit a bounded request and retrieve its metadata status | Exact device or separate plugin grant; never releases a secret |
| `use` | Mediated secret execution/release | Denied by this slice for every ring; reviewed one-use step-up work remains required |

Rights are independent sets, not ranks. Discovery does not imply request,
replication or use; replication does not grant a WispKey execution capability.
Plugin identity/consent is distinct from its transport device and account session.

Effective permission is the intersection of authenticated endpoint/account,
portable vault/project/partition identity, approved device and exact key versions,
plugin principal if applicable, owner grant, current classification, resource and
credential revision, exact origin, operation, existing host/path/method policy,
auth lifecycle, finite session/grant/enrollment expiry, current epoch/policy,
freshness, and explicit opt-in. A single denial denies. Apply at admission **and
again at actual export, decryption/import commit, token resolution and release**.
A caller-supplied device ID, account label, ring, approval boolean, or arbitrary
`Ready` cannot satisfy these facts. The Python model accepts already-verified
synthetic facts, never wire input; its booleans are deliberately not an adapter.

Bindings use immutable opaque IDs; display names do not select authority. Bind
API endpoint/audience and authenticated account (including issuer namespace),
vault, project, partition, device, distinct recipient/authentication keys, owner
root fingerprint, epoch and policy revision. Account, endpoint, scope or key
changes invalidate the old grant. Exact-origin checks include scheme/host/port;
future adapters must reuse canonical origin validation and reject userinfo/path
ambiguity. Existing auth provider/account restrictions remain independent checks.

Restricted/critical mediated use will require fresh trusted-device presence or a
reviewed stronger step-up and an atomically consumed approval binding requester,
device/plugin, target, operation, credential/policy revisions, epoch, nonce and
expiry. Session unlock or email login alone is insufficient. That execution
protocol is deliberately denied, not stubbed with an `allow` boolean here.

## Enrollment state and pairing

Proposed pending record fields: contract/purpose, endpoint/audience/account,
request ID, CSPRNG request nonce, device ID, recipient public key, separate request
signature public key, owner root reference, requested exact scope/rights,
policy/epoch, human-readable description, created/expiry times, state and CAS
revision. Description is untrusted display text, length-bounded and escaped, not
an identity proof. Requests and approval transcripts are immutable.

Candidate flow (must receive cryptographic and UX review before implementation):

1. Secondary signs into the account, creates dedicated local recipient and request
   authentication keys through reviewed libraries, and submits a pending request.
   This yields no vault content, key wrapper, trust, plugin grant or elevation.
2. Primary authenticates the account and views exact request, scope, rights and
   key fingerprints. Secondary pins the existing owner root out of band using a
   full-fingerprint comparison or QR exchange from the trusted primary. Primary
   must also authenticate the secondary request/key transcript out of band.
   Comparing only a server-supplied device description is insufficient.
3. Prove possession of both proposed keys and bind it to this transcript. An age
   challenge encrypted to the proposed recipient plus a separate signature proof
   is a candidate, **not a finalized custom handshake**. The exact challenge,
   transcript encoding and relay-resistant user comparison remain review gates.
   A signature under the secondary's unrelated signing key alone does not prove
   possession of its X25519 private key. Never convert/reuse one key across roles.
4. After current owner presence and explicit export consent, primary signs the
   immutable approval transcript. It binds both keys, full account/scope, owner
   root, request/nonce, rights, policy/epoch and finite expiry. Cloud verifies
   public proofs and atomically transitions only the still-pending revision.
5. Secondary verifies owner signature against its pinned root and full local
   transcript, and the primary rechecks current authority before creating the
   first snapshot. Neither server receipt nor UI approval alone releases data.

A QR contains public, bounded transcript data only; never keys/passphrases or a
reusable bearer enrollment capability. Forwarding someone else's QR cannot be
made safe by cryptography alone; UI must expose who/what is being paired. Do not
call this an OAuth device authorization grant. Headless secondaries can display
an authenticated public transcript for owner comparison, but cannot self-approve.
An unattended primary cannot silently substitute cached unlock for presence.

| State/event | Required behavior |
|---|---|
| Pending -> approved | Exact signed request, current owner authority/presence, comparison and both-key possession, before expiry, CAS revision succeeds |
| Pending -> expired | `now >= expires_at`; no late approval |
| Pending -> revoked | Owner denial/revocation or authenticated request cancellation; retain a tombstone |
| Approved -> revoked | Owner revocation or valid originating cancellation; no subsequent release/import |
| Approved -> expired | Finite grant/enrollment deadline reached; no silent renewal |
| Expired/revoked -> any active state | Forbidden; explicit new request/identity/grant, with new nonce and reviewed epoch |

Cancel/revoke callers must be authorized before invoking the pure transition.
The model tests serialization, not database concurrency. Production must CAS in
one transaction, including owner authority/revocation revision. If approval wins
first, cancellation must revoke that resulting approval after re-reading; it
cannot be discarded as a stale cancel. If cancellation wins, approval fails.
Duplicate approval may return a stored receipt but cannot mint another grant or
extend expiry. Terminal IDs/nonces cannot be reused. Approver revocation racing
approval must be ordered against issuance by the same authority transaction.

The model proposes a maximum pending lifetime of 300 seconds and, conservatively,
keeps approval expiry within that same request deadline. This is a short-session
contract, **not persistent enrollment UX**. Durable approved device records and
separate grant renewal lifetimes require review before implementation. Wrong
account/issuer, altered keys/scope/description, expired request, stale revision,
missing possession/presence/comparison or self-approval all fail closed.

## Candidate encrypted snapshot and signed envelopes

Each snapshot is a fresh age file encrypted only to the exact approved secondary
recipient. The owner keeps its source vault; no extra owner/cloud recipient is
silently added. Use the library to generate fresh per-file key/ephemeral material,
finish and authenticate the entire stream. Never reuse an old file key to update
payloads; retries resend the identical journaled ciphertext instead of encrypting
new bytes under an old sequence. Do not wrap the old shared bundle passphrase.

Proposed manifest fields, all signed by the pinned owner's Ed25519 key:

- Contract and message purpose (`snapshot`, distinct from `enrollment-approval`,
  `policy-head`, `rotation`); fixed crypto suite identifiers and payload format
- Full binding described above, grant/request ID and recipient key fingerprint
- Epoch and monotonic sequence for that binding, policy revision and minimum
  reader version, snapshot ID, ciphertext SHA-256 and byte count
- Issued/expiry timestamps and approved exportable routine scope

Sign exact bounded payload bytes and transport those bytes plus signature in a
strict envelope, following the existing ring verification pattern. Verify the
signature before using parsed claims. Proposed envelope payload is strict UTF-8
JSON encoded with canonical unpadded base64; reject duplicate keys, unknown fields,
non-integer/out-of-range counters, invalid encodings, trailing data and unsupported
versions/purposes/suites. No JSON reserialization is used as signature input. Exact
field spellings, identifier encoding, integer ranges, envelope/body limits and
cross-language byte vectors remain wire-format review blockers; draft model
objects are not that wire format. Do not implement home-grown canonicalization.

The encrypted payload repeats the authorization binding and includes its policy,
portable credential/auth IDs and revision/lifecycle restrictions. Verify complete
ciphertext length/hash, signature, full age authentication, payload binding and
current policy before atomic import. No partial plaintext import during streaming.
Stage only in bounded memory or protected encrypted storage. Reject any dependency
or retained identity that would lose restrictions, change account, or clear a
terminal revocation. Preserve existing encrypted retry journaling and atomic
fingerprint/revision checks; do not reuse `WKCS` version numbers for this protocol.

The owner serializes sequence allocation and durable journal creation. A sequence
identifies one immutable ciphertext/manifest. Same epoch/sequence with different
hash is equivocation; identical verified current head is an idempotent no-op.
Skipped sequences are acceptable for full snapshots only when a fresh owner head
names the exact new tuple. Lower sequences are rejected. Epoch changes require
an explicit authenticated transition, not accepting the largest untrusted number.

## Freshness, revocation, rotation and recovery

Candidate first-slice freshness: **online primary required**. Secondary requests a
nonce-bound owner-signed head binding account, device/grant, scope, epoch, policy
revision and current sequence/hash. Match a locally outstanding one-use challenge;
Cloud cannot mint or refresh it. A frozen server-signed timestamp is insufficient.
Candidate maximum local monotonic lease is 30 seconds, bounded further by all
signed expiries and finite session expiry. At the exact deadline deny. A new
challenge must not extend authority if the owner has revoked it. Restart,
clock uncertainty/rollback, missing protected checkpoint, logout, lock, account
switch, cancellation, restore or conflict invalidates cached admission.

This gives a proposed **up to 30-second stale-authority window** for a previously
issued lease if a revocation is not yet observed. Observed revocation stops action
immediately at the next check. No claim of instantaneous remote revocation or
atomic recall of bytes already sent is made. The budget is unapproved. A stricter
zero-offline-use promise needs owner authorization per actual release, not this
lease. For restricted/critical use no offline lease is enabled at all.

Store the last accepted epoch/sequence/hash and policy floor atomically with the
import. A first or restored reader gets a baseline only from a fresh nonce-bound
owner head plus current approval. It must not trust R2's latest pointer or a local
backup checkpoint as proof of currentness. The pure snapshot model assumes this
baseline already exists; baseline provisioning is an integration gate.

Revoke a device and stop publishing to its recipient. Subsequent snapshots use
fresh file keys and newly approved recipients; there is no shared partition key
to retain. Rotate a recipient/authentication key through new proof/comparison and
approval, advance the epoch, and invalidate outstanding requests/grants/journals.
Old ciphertext remains decryptable by old holders; rotate the underlying provider
secret when required. Do not reinterpret an unacknowledged old upload in a new
epoch. Reconcile its old receipt without releasing new authority.

Owner root rotation requires explicit old-root-authorized transition and new-root
out-of-band confirmation; suspected compromise requires an independent recovery
anchor, not trusting a signature by the compromised root alone. Do not silently
accept a replacement root supplied by Cloud, account recovery or a restored vault.
The first slice supports no root rotation or lost-all-devices recovery action.

Backups/export preserve classification, policy floor, identities and terminal
revocation metadata, but never restore remote consent, sessions, grants, presence,
nonces or automatic sync opt-in. Imported unknown/legacy data is restricted;
newly managed partitions reject old envelopes even after deleting their last
managed row. Recovery is owner-only and starts disconnected. A future reviewed
recovery kit must define independent recovery material, storage, loss/compromise
handling and re-enrollment. Email/SSO reset alone cannot decrypt or restore trust.
No recovery key is generated in this work.

## Compatibility, routes and integration gates

Before managed replication can be enabled, maintain a durable server/client
protocol floor. Legacy account-only project, partition, manifest, payload, share,
export and old sync/watch paths must reject managed data or route through the
same device evaluator. A legacy endpoint cannot list managed inventory, issue a
wrapper, overwrite/delete a managed object, or downgrade its floor. Audit every
alias and administrative path; protecting only a new endpoint is insufficient.
Use separate namespaces for legacy owner sync and managed replicas, with no
implicit conversion. Account bearer-only access must not become owner authority.

Local owner recovery/export remains a distinct, explicit trusted-owner operation;
an enrolled secondary cannot select it through a request flag. Secondary data
must not enter an ordinary unrestricted owner vault where `exec`, MCP, proxy,
browser fill or export can bypass replica provenance. Before any import adapter,
review managed ciphertext markers and shared release checks across all surfaces.
There are no runtime enforcement changes in this proposal.

Metadata-only audit: fixed event/deny categories, opaque account/device/plugin,
request/grant, scope IDs, policy/epoch and operation, timestamp and outcome.
Exclude descriptions, labels containing personal data, keys, secret values, tokens,
challenge proofs, payloads and decrypted provider errors. Inventory needs owner
visibility of pending/approved/expired/revoked devices and key fingerprints through
a separate authorized view; default plugin inventory is narrower. Transport errors
must not echo untrusted headers/bodies. Full audit integration is unimplemented.

OS storage: existing Keychain/Windows keyring support does not establish
non-exportability for new Ed25519/X25519 keys. Explicitly review macOS Keychain,
Windows credential protection, Linux secret-service/file fallback, headless
availability, backup exclusion, owner-only ACLs and process-memory handling.
No Secure Enclave/TPM or hardware-backed claim is made for software age identities.
Presence UI and actual key operations must be bound, not inferred from an OS name.

## Review decisions required

1. Accept exportability and one primary/one secondary, or require a non-exportable
   remote execution design instead. Confirm ring names and default classifications.
2. Review age library/version/features/platform support and the complete pairing,
   proof-of-possession, signed-envelope and root-pinning protocol. Supply real
   interop and negative cryptographic vectors. Select hardware requirements.
3. Approve freshness threat model, primary-online constraint, 30-second budget,
   300-second request/session cap and eventual persistent enrollment/renewal UX.
4. Review identifiers, wire limits, provenance markers, downgrade floors, policy
   serialization, auth/profile compatibility and legacy-route migration with core
   and Cloud owners. No schema reservations are made by this draft.
5. Specify root/key rotation, recovery kit and compromise response, or keep each
   unavailable. Confirm all-device-loss behavior is clearly communicated.
6. Review test results and adversarial plan, then authorize runtime integration in
   separate disabled-by-default changes. Publishing a PR remains parent-gated.

## Run and interpret the suite

From the repository root, with Python 3.10+ and no third-party packages:

```sh
python3 -B -m unittest discover -s docs/contracts/access-enrollment-v1 -v
```

No setup credentials, environment variables, vault initialization, Cargo build,
service, browser, network or filesystem data beyond these source fixtures are
needed. Tests use reserved `.test` endpoints and symbolic public-key/hash IDs;
**these are policy vectors, not valid crypto material**. `vectors.json` has 47
portable decision cases applied to the fixture in `test_policy_model.py`.
The 19 test methods also enumerate independent right subsets, exact scope/key
binding, state transitions, release-time changes and snapshot ordering. See
[the adversarial/integration plan](TEST-PLAN.md) for unimplemented checks.
