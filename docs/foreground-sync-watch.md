# Experimental foreground encrypted sync watch

Build with `--features experimental-sync` to use this bounded, explicitly invoked
owner workflow. Default builds do not include `cloud watch`. The command polls
existing conditional encrypted snapshot APIs; it does not need a new server feed.

## Pair manually, then opt in for one bounded run

First complete a successful manual `cloud push`/`cloud pull` on each owner's vault
using the same separate bundle passphrase, as described in [cloud sync](cloud-sync.md).
An account login or an error-created tracking row is insufficient. Watch requires
a real acknowledged revision, local fingerprint and successful sync timestamp,
with no pending upload or unresolved conflict at startup.

```sh
wispkey cloud watch personal \
  --bundle-passphrase-file /private/cloud.pass \
  --for-seconds 300
```

`--bundle-passphrase-file` is required and uses the existing bounded owner-private
file reader (16 KiB maximum). Neither a passphrase value in arguments nor
`WISPKEY_BUNDLE_PASSPHRASE` fallback is supported. `-` is not a stdin alias. The
passphrase must contain at least 12 characters and is held in zeroizing buffers
for the run. It is never sent to Cloud or printed. Protect the source file with
owner-only permissions and retain it only under your own chosen storage policy.

The duration is 1–3600 seconds (default 300), further bounded by the current finite
vault session's expiry. Watch never unlocks or renews a session from
`WISPKEY_PASSWORD`, a password file or a remembered protector. Run a normal owner
unlock separately when needed. Zero-timeout/unbounded vault sessions cannot start
watch. Every invocation is a fresh process-local opt-in; no daemon, startup entry,
persistent approval, device enrollment or grant is created.

## Safety and observable behavior

The command pins the endpoint, authenticated account/token/configuration, current
session revision, active project and local project/partition UUIDs. Startup verifies
the token's account against the server. Account switch, logout, local session lock,
expiry/renewal, scope switch or delete/recreate stops the run rather than rebinding
it. Guard checks occur before local snapshot access, network dispatch, payload
decryption, upload journaling, upload acknowledgement and atomic import commit.
The import commit check is inside the SQLite write transaction so a denial rolls
back both credentials and acknowledgement.

Polling is at most once per second after each completed attempt. Network failures
use the coordinator's bounded exponential backoff (2–300 seconds). Only transient
network failures retry. Authentication, corruption, policy/import errors and
revision conflicts stop the command; it never picks a conflict winner or invokes
resolve/recover. Concurrent changes retain the existing explicit-recovery workflow.

The requested deadline and Ctrl-C cancel pending asynchronous work. CPU-bound
cryptography is checked at the next guarded boundary; the duration is not a hard
real-time process-kill guarantee. A request already sent may have reached Cloud.
An interrupted upload retains its exact encrypted journal/mutation ID for manual
reconciliation; stopping never claims the write was rolled back. Guard checks
cannot atomically retract bytes sent just before an external lock.

A requested-duration stop has the same outcome whether the asynchronous timer or
a synchronous guard notices it first. It never acknowledges the interrupted
attempt. Expiry of the owner session remains an authorization failure, including
when that expiry shortens the requested duration.

Duration/cancellation returns a final metadata-only JSON report: stop reason,
successful-attempt count (including attempts with local changes still pending)
and the last local sync result. Failures return a nonzero exit with an error on
stderr. `reconciliation_required: true` deliberately
remains set on duration/cancellation: the last acknowledged result does not prove
all devices are current or that an interrupted request was absent. Existing
`cloud status --remote` and manual `cloud sync` provide reconciliation/recovery.

## Trust boundary and remaining work

This slice uses the existing manual owner/shared-passphrase trust model. It is not
cryptographically approved device enrollment and must not be advertised as meeting
Cloud #5. It does not invent access-ring names/defaults, step-up grants or ring
permissions. Auth registry IDs, origins, expiry and terminal revocation remain in
the existing authenticated snapshots and existing release enforcement.

It advances [#48](https://github.com/rankupgames/wispkey/issues/48) beyond the
[metadata coordinator](realtime-sync-coordinator.md) with two-client synthetic
transport tests. Still outstanding: reviewed ring enforcement, trusted enrollment
and minimum key distribution, approved background key access, durable automatic
opt-in/cursors, server notifications, integrated status UI and a measured online
propagation target. Existing plaintext or old keys cannot be remotely erased.

## Verification

`cargo test --locked --all-features --test cloud_sync watch` exercises real CLI
clients against synthetic loopback Cloud storage. The core
`cloud_apply_guard_denial_at_commit_rolls_back_credentials_and_journal` test proves
rollback when authority disappears at the transaction's final guard. The typed
duration-deadline rollback test covers that same boundary without committing
credentials or journal state. Deterministic watch unit tests inject exact-boundary
time before transfer and before acknowledgment, verify session expiry stays an
error, and retain network backoff without advancing the cursor. Run the full
existing default/all-feature suites to check compatibility of the shared manual
sync/import path; watch is excluded from default builds.
