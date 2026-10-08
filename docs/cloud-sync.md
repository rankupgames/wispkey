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

## Failures and retry policy

Manual `push`, `pull`, and `sync` make one transfer attempt per partition. They
never loop automatically. Each HTTP request has a 30-second timeout. A failed
transfer leaves its acknowledged revision unchanged; an uncertain upload keeps
its encrypted payload and mutation ID so repeating the same command can reconcile
or resend that exact upload. A successful receipt is required before acknowledgement.

| Failure | Local `last_error` | Foreground watch | Recovery |
| --- | --- | --- | --- |
| Transport interruption | `network_interrupted` | Bounded retry | Check connectivity, then repeat the same command. |
| Request timeout or HTTP 408 | `request_timed_out` | Bounded retry | Repeat after the connection or service recovers. |
| HTTP 500, 502, 503, 504 | `service_unavailable` | Bounded retry | Inspect service health before repeated manual attempts. |
| HTTP 401 | `authentication_expired` | Stops | Run `cloud login`, then inspect status and retry. |
| HTTP 403 | `permission_denied` | Stops | Check account permissions and plan; retry does not grant access. |
| HTTP 429 | `rate_limited` | Stops | Wait for the service limit to reset before a new manual attempt. |
| HTTP 409 or 412 | `conflict` | Stops | Inspect the remote revision and explicitly resolve the conflict. |
| Unsupported response or revision contract | `protocol_rejected` | Stops | Check CLI/backend compatibility; do not force an upload. |
| Invalid payload, local guard, or vault failure | `sync_failed` or a local error | Stops | Correct the reported condition; local data remains unchanged. |

The default-off [foreground watch](foreground-sync-watch.md) uses the same
conditional transfers. It waits 2, 4, 8, 16, 32, 64, 128, 256, then 300 seconds
between consecutive transient failures. The delay stays capped at 300 seconds;
a successful reconciliation resets it. The requested duration (at most 3,600
seconds) and existing vault-session expiry bound the whole run, including in-flight
requests. There is no retry after an authorization, rate-limit, protocol, conflict,
or local guard failure. Watch startup account verification also fails immediately;
it does not start an unverified watch or retry login.

Errors and journal categories use fixed text. Provider response bodies, URLs,
bearer tokens, and plaintext credentials are not copied into them. After a cancelled
or expired watch, run manual sync to reconcile a possibly pending upload. Never
choose a conflict winner solely to clear a service error. If service failures
continue across bounded runs, stop restarting watch and have the Cloud operator
check availability and protocol compatibility.

The sync maintainers own this policy in `src/cloud/sync.rs` and the watch coordinator.
Rerun `cloud_sync` and the Cloud watch/coordinator unit tests when request handling,
status mapping, backend revisions, or retry limits change. The lost-acknowledgement
fixture covers transport, service, authorization, rate-limit, and protocol failures;
the watch fixture checks retry admission and unchanged acknowledgement state.

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
