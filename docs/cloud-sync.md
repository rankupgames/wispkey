# Encrypted partition synchronization

Cloud sync requires a backend implementing conditional partition revisions and
payload download.
Deploy its reviewed database migration before enabling the new Worker. An older
backend is incompatible; the CLI does not fall back to unconditional uploads.
Local vault, proxy, injection, and sharing commands continue to work offline.

## First device and another device

Use a strong sync bundle passphrase shared between your own devices. It is
separate from each device's vault master password and is never sent to the
backend. Keep it in a password manager or an owner-only file. Losing both the
passphrase and local vault data makes the encrypted remote snapshot unrecoverable.
The minimum is 12 characters; use a long, randomly generated value.

```sh
wispkey cloud login
wispkey project use client-alpha
wispkey cloud push production --bundle-passphrase-file /private/cloud.pass
wispkey cloud status --remote --format json
```

Login verifies the returned session with the backend and records its authenticated
account ID and current plan claims. It does not change billing. API URLs must be
HTTPS; literal loopback HTTP is accepted for fixtures. Redirects and environment
HTTP proxies are disabled so the bearer token cannot follow a redirected request.

On another initialized vault, create/use the same WispKey project name, then pull
using the same sync passphrase. The vault master password can differ between
devices. A missing partition is created only inside the successful import
transaction. An existing empty partition can receive its first snapshot.

```sh
wispkey project create client-alpha
wispkey project use client-alpha
wispkey cloud login
wispkey cloud pull production --bundle-passphrase-file /private/cloud.pass
```

`WISPKEY_BUNDLE_PASSPHRASE` also supplies the sync passphrase for trusted
noninteractive use. `WISPKEY_PASSWORD` only unlocks the local vault; it is never
used as the sync passphrase. Without a passphrase file/environment variable, the
normal hidden bundle prompt is used.

Push and pull bind to the active project's exact name and partition name. A
stable opaque remote ID derives from the API endpoint, authenticated account,
and those names, allowing different accounts to use the same names independently.
The authenticated backend account owns the record. The encrypted payload also binds the exact project and
partition so a server cannot substitute another partition's valid bundle.
Renaming a project or partition creates a different sync identity; inspect and
explicitly migrate such changes rather than expecting a remote rename.

## Routine synchronization

```sh
wispkey cloud sync --bundle-passphrase-file /private/cloud.pass
wispkey cloud status
wispkey cloud status --remote --format json
```

`sync` processes only explicitly tracked partitions in the active project.
Initial push or pull opts a partition into tracking. Local-only changes upload;
remote-only changes download; concurrent changes conflict. Push refuses a
changed remote revision, and pull refuses to discard local changes. Repeating a
successful operation without changes does not rewrite remote data or local
credentials. A multi-partition sync commits each partition separately and stops
at the first error; earlier acknowledged partitions remain committed.

Local status reads the journal without contacting the service. Remote status
checks authenticated backend metadata and requires an unlocked vault. Status
distinguishes acknowledged revision, last success, last error, local/remote
pending changes, a pending upload, and conflict. Locked local status reports
unknown local-change state instead of claiming the partition is unchanged.
Status does not expose bundle contents, passphrases, bearer tokens, or a pending
upload body.

## Conflicts and recovery

Inspect `cloud status --remote --format json`, then supply the **observed**
`remote_revision` when choosing a side. Use `absent` only when status reports
that the remote record is absent. A different revision at execution time rejects
the resolution; it is never refreshed and overwritten automatically.

```sh
wispkey cloud resolve production --keep local --remote-revision <observed-revision> \
  --bundle-passphrase-file /private/cloud.pass
wispkey cloud resolve production --keep remote --remote-revision <observed-revision> \
  --bundle-passphrase-file /private/cloud.pass
```

Before replacing either side, the command preserves the discarded snapshot in an
owner-only encrypted `cloud-recovery-<uuid>.wkcs` file in the vault directory and
returns its path. Keeping local first downloads and authenticates the remote
copy. Keeping remote encrypts the current local copy. A failed resolution may
leave an additional recovery file; it never deletes recovery material on failure.

Restore a recovery file into its original active project, offline if needed:

```sh
wispkey cloud recover /private/cloud-recovery-<uuid>.wkcs \
  --bundle-passphrase-file /private/cloud.pass
```

Recovery authenticates the file, preserves another encrypted copy of the current
local partition, and atomically restores the saved snapshot. It does not modify
the remote partition or claim a sync acknowledgement. An uncertain upload must
be reconciled before recovery is allowed. Review pending changes before the next
sync. Recovery files are separate from sharing bundles and from
full-vault backup archives; retain them separately while they are needed.

## Interrupted operations and guarantees

- Uploads use a random-salt Argon2id/AES-256-GCM `WKCS` bundle. Credential values,
  website-login payloads, types, host restrictions, lifecycle metadata and opaque
  wisp tokens are inside the authenticated encryption. Only the partition name,
  opaque ID, ciphertext hash/size, revision and mutation ID are sent as metadata.
  The master password/key and general vault contents are never uploaded.
- Before uploading, the exact encrypted request, mutation ID, base revision and
  local fingerprint are journaled inside the local vault database. A lost
  acknowledgement leaves that request pending. Retry the same command: identical
  retries can recover their receipt; an intervening remote write conflicts.
  Local edits made meanwhile remain pending and are reported for the next sync.
- Pull checks the revision, byte count, ciphertext hash, authenticated encryption
  and payload scope before changing credentials. Under SQLite's write lock it
  rechecks the local fingerprint, then imports credentials and the acknowledged
  manifest in one transaction. A later invalid row, collision in another
  partition, concurrent local edit, or database error rolls back the entire
  import. It never moves a same-named credential out of another partition.
- Existing credential IDs are retained by name within the partition; opaque
  tokens and metadata follow the authenticated snapshot. Missing credentials are
  removed only when applying an accepted snapshot. Local instance identities,
  grants, policies and audit history are not imported from another device.
- Local fingerprints are keyed HMACs, not plaintext hashes suitable for guessing
  low-entropy secret values. Journal errors are fixed categories. Provider error
  bodies and transport URLs are not echoed or persisted.
- A process lock serializes sync commands in one vault; ordinary local edits
  remain possible and are checked before commit. Requests have bounded timeouts
  and response sizes. There are no automatic conflict retries.
- For expired authentication, log in again to the same account and retry. Do not
  delete the journal or switch accounts to clear an error. State is scoped to
  API URL, authenticated account, project and partition. A different account or
  endpoint starts a separate binding and cannot reuse the old acknowledgement.

Cloud clients track at most ten acknowledged partitions for the Cloud tier;
existing tracked partitions remain updatable at the limit. The backend enforces
plan access. Server-side billing quotas, immutable-object garbage collection,
organization sharing, remote rename/delete UX and production rollout are separate
operational/product work; this feature synchronizes account-owned partitions.

## Validation

`cargo test --locked --test cloud_sync --test cli_contracts` exercises real CLI
processes against a loopback HTTP fixture: encryption/redaction, first/no-op sync,
cross-device import, lost acknowledgements, concurrent edits, explicit choices,
recovery copies, corruption/wrong passphrase, expired authentication, and atomic
rollback. Its ignored child test is invoked by round-trip tests with synthetic
stdin to check the decrypted value without printing it; do not run it standalone.
The backend's separate fixtures exercise real local D1/R2 concurrency and the
existing-schema migration. These tests do not log into production Clerk or deploy
a Worker.

## Realtime coordinator foundation

The optional `experimental-sync` feature compiles a metadata-only scheduler contract.
It does not enable automatic sync or enroll devices. See
[the contract and remaining activation gates](realtime-sync-coordinator.md).

Experimental builds can opt into a time-bounded owner-run polling session with
[`cloud watch`](foreground-sync-watch.md) after manual pairing. This is distinct
from device enrollment and is unavailable in default builds.

## Browser login

Cloud authentication uses the opt-in public OAuth code + S256 PKCE contract in
[Cloud CLI sign-in](cloud-login.md). Legacy raw callback sessions need a fresh
login. Access tokens expire within 24 hours; no refresh token is requested.

## Manifest and conflict contract

This table records the current conditional-sync contract for RUG-218. Review
approval remains a release gate; this document does not introduce a new wire
format or authorize a schema migration. RUG-5 owns sync implementation. The
project maintainer owns contract review and must review changes to identity,
revision handling, encryption, storage or conflict decisions.

| Field / identity | Current meaning |
| --- | --- |
| Endpoint and authenticated account | Define a separate journal scope; changing either cannot reuse another scope's acknowledgement |
| Project and partition names | Exact names bind both the opaque remote ID and authenticated encrypted snapshot; a rename requires explicit migration |
| Remote `id`, `revision` | Remote ID must match the requested record. Revisions are opaque 32/36-character hexadecimal/hyphen tokens; compare for equality, never lexical or time order |
| Remote `content_hash`, `size_bytes`, `last_mutation_id` | Bind downloaded ciphertext and acknowledge the exact mutation; payload limit is 6 MiB |
| Local `revision`, `local_hash` | Last acknowledged remote revision and keyed local snapshot fingerprint, not the current remote state or a plaintext secret hash |
| Local `last_success`, `last_error`, `conflict_revision` | Success time, fixed error category and observed conflict marker; an error never advances acknowledgement |
| Local `pending` | Exact encrypted upload, mutation ID, expected revision and local fingerprint, persisted before dispatch |
| Result `outcome`, `local_changes_pending`, `recovery_path` | Uploaded/downloaded/unchanged result, edits still awaiting sync and optional encrypted recovery artifact; an acknowledgement can coexist with later local edits |

A fresh empty partition has no credentials and no signup-profile state.
There is no remote ancestry graph. The acknowledged revision is the comparison
base; an opaque unequal revision has no inferable ancestor/descendant order.
A pending upload reconciles its exact mutation before an ordinary new decision.

| Local versus acknowledged fingerprint | Remote versus acknowledged revision | Ordinary `sync` decision |
| --- | --- | --- |
| Equal | Equal | No-op; preserve both sides |
| Changed | Equal | Conditional upload against the acknowledged revision |
| Equal | Changed | Authenticate and atomically import the remote snapshot |
| Changed | Changed | Conflict; preserve both sides and require an explicit choice |
| No acknowledgement; local missing or fresh empty | Remote exists | First pull may create/import the partition atomically |
| No acknowledgement; local populated | Remote absent | First push uses `If-None-Match: *` |
| No acknowledgement; local populated | Remote exists | Conflict; no implicit winner |
| Invalid metadata, ciphertext, scope or local import | Any | Fail without importing or claiming acknowledgement |

Explicit `push` refuses changed remote state; explicit `pull` refuses local
changes except a fresh empty partition without signup-profile state. Resolve
requires the exact observed
remote revision, or `absent` after observing absence. It preserves the discarded
side in an owner-only encrypted recovery file before replacement. A changed
revision, malformed receipt, invalid bundle or concurrent local edit stops the
operation. Import and acknowledgement commit together. Uncertain uploads must
be reconciled before offline recovery; recovery never acknowledges remote state.

The journal identity prefix is `cloud_sync_v1` and the remote ID derivation is
`wispkey-partition-v1`. Encrypted `WKCS` snapshots currently accept versions
1 through 3. These are separate contracts, not interchangeable version numbers.
An older backend without conditional revisions is incompatible; HTTP 428 fails
closed. Unsupported snapshot versions fail authentication/scope validation.
There is no unconditional-upload fallback, automatic identity migration or
silent format downgrade. A future format change needs approved migration and
fixture updates before an old format can be deprecated.

Representative fixtures in `tests/cloud_sync.rs` cover no-op equality,
interrupted acknowledgement with identical ciphertext/mutation, concurrent
changes, explicit local/remote choices, edits during download, corrupt or wrong
passphrase input and rollback of a later invalid row. Preserve these fixture
scenarios across any version change; synthetic fixture success does not approve
a new schema or certify production storage.

## Offline behavior contract

This table records existing behavior for RUG-228. RUG-5 owns implementation and
RUG-84 owns the trust-boundary proof sequence. The project maintainer owns the
contract and reviews startup, identity, storage, sync and retry changes.
The [Personal proof PR](https://github.com/rankupgames/wispkey/pull/77) supplies
the independent denied-network procedure; approval of this table remains a
release review gate.

| State / event | Local behavior and safe next action |
| --- | --- |
| Personal, no account or network | Local vault/credential operations remain available; proxy upstreams must be locally reachable |
| Cloud configured, network unavailable | Local commands remain available. Explicit network operations fail; local status reads the journal and does not claim remote verification |
| Missing or expired local Cloud session | Network requests reject locally; sign in again to the same account. No offline access expansion |
| Upload journaled, response lost | Exact encrypted request stays pending. A new process retries it with the same mutation and base revision; do not delete the journal |
| Offline local edits after uncertain upload | Preserve the edits; receipt recovery acknowledges the prior snapshot and reports current edits as still pending |
| Download interrupted or invalid | Preserve the current local partition and acknowledgement; retry only after the failure cause is resolved |
| Reconnection reveals concurrent changes | Report conflict and require observed-revision resolution; reconnect never chooses a winner |
| Vault locked | Local status reports unknown local-change state. Network sync/import still requires local unlock and existing authorization |
| Offline encrypted recovery | Restore atomically in the original project using the separate bundle passphrase; uncertain uploads block recovery first |
| Experimental foreground watch interrupted | Transient network errors use bounded backoff. Authority loss or conflict stops the run; restart requires fresh explicit owner opt-in |

Default builds do not queue a background sync job or acquire keys on reconnect.
The durable queue is the encrypted pending upload for an explicitly attempted
operation, not a promise that later local changes will upload automatically.
Foreground watch is feature-gated and process-local; see
[its authority and cancellation contract](foreground-sync-watch.md).
The safe recovery sequence is local status, restored connectivity, remote
status, retry/reconciliation, then explicit resolution if needed. Do not erase
journals, recovery files or account bindings to clear an error. No failure,
retry or status output may include provider response bodies, credentials,
passphrases or bearer tokens.

Acceptance scenarios are deterministic: remove the acknowledgement after a
stored upload and compare retry bytes; edit locally while a download is in
flight and require rollback; alter remote revision before resolution and
require rejection; deny network with no account configuration and verify local
operations; stop watch at authority/deadline boundaries and retain pending
reconciliation. Existing sync/watch fixtures cover the Cloud scenarios, and
PR #77 adds the independent Personal network-denial scenario. Rerun after the
review triggers above and before release acceptance. Actual live session and
deployment acceptance remain with RUG-220 and RUG-83.
