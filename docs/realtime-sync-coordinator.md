# Experimental realtime sync coordinator

This is a scheduling foundation for [#48](https://github.com/rankupgames/wispkey/issues/48),
with fail-closed admission states for the future
[access policy](https://github.com/rankupgames/wispkey/issues/49) and
[device enrollment](https://github.com/rankupgames/wispkey-cloud/issues/5) adapters.
The coordinator itself is a metadata-only module behind `--features experimental-sync`;
default builds exclude it. The separately documented foreground watch is its first
CLI caller. Compiling the feature does not start a daemon, enable network activity
or authorize any device. Enrolled-device background synchronization remains unimplemented.

## Implemented contract

One coordinator represents one explicitly selected partition. Its exact endpoint,
authenticated account, enrolled device identifier, project and partition form the
binding. Notifications cannot replace that binding. The adapter must cap its set
of opted-in coordinators (initially no more than the existing ten-partition limit).
All newly created or restored coordinators start disabled, including when their
checkpoint came from a backup. Manual tracked partition history is not auto-sync
consent.

Hints contain only a scope and an opaque bounded ASCII cursor (1–256 bytes).
Duplicates coalesce, and there is one pending cursor rather than an unbounded
queue. Reordered hints can cause an extra reconciliation, never choose which
snapshot wins. The contract assumes an authenticated account-scoped feed and a
full authenticated current-revision reconciliation; it is unsuitable for delta
application or treating lexical cursor order as server order. A future transport
must bound wire bodies before deserializing them.

The adapter borrows the coordinator through a single-use attempt while reconciling.
This prevents a concurrent dispatch or overwritten hint in that instance. Dropped
attempts remain pending. Hints received during reconciliation must be held by a
bounded transport or recovered through the mandatory periodic reconciliation.
Only a full successful current-revision reconciliation with rechecked admission
acknowledges a cursor. A transaction reporting local changes still pending uses
`Reconciliation::Pending` and retains the unacknowledged hint.
Persist that metadata after the existing sync transaction commits. A crash before
checkpoint persistence safely reconciles again on restart. The checkpoint itself
contains no keys, grants, trust, opt-in or authority.

Failed attempts preserve the old checkpoint and retry after exponential delays
from 2 to 300 seconds. Hints cannot bypass that backoff. Successful reconciliation
limits another dispatch to at least one second later and schedules unconditional
reconciliation after 60 seconds, covering lost notifications and reconnects.
These are provisional planner intervals, not a measured end-to-end propagation
SLO. The adapter supplies a process-monotonic clock; checkpoints do not serialize
process clock values. Conflict is latched independently of routine admission refresh and blocks dispatch
until the adapter reports explicit reviewed resolution through `conflict_resolved`.

## Required adapter gates before activation

The `Admission` enum is a trusted adapter input, **not an authorization evaluator**.
No wire field, account sign-in, client label or arbitrary boolean may establish
`Ready`. The future adapter must check all of the following at dispatch and again
before applying a result:

- Explicit current project/partition opt-in
- Current authenticated endpoint/account and cryptographically verified device
  enrollment with authorized scope
- Current ring and existing policy intersection, revocation, expiry and freshness
- Current owner-approved local key access without passphrases in process arguments
  or environment; Cloud must never obtain vault/sync keys
- Existing conditional revision, encrypted retry journal, authentication and atomic
  import checks, preserving auth IDs, revisions and terminal revocation

Do not use a cached `Vault::is_unlocked()` result as current owner authority: the
object can retain a key after an external lock or session expiry. Likewise,
`CloudClient::synchronize_partition` currently resolves the active project when it
executes; a future adapter needs explicit scope through dispatch and commit rather
than silently following a changed active project. Device identity is a binding,
not proof of enrollment. Restoring metadata never restores an approval.

## Remaining acceptance criteria

The coordinator and foreground adapter do not complete #48, #49 or Cloud #5.
Outstanding enrolled-device/background work includes:

1. Review ring policy names, defaults, format, shared enforcement, one-use step-up,
   and the freshness budget; no ring names or grant semantics are finalized here
2. Review enrollment pairing, user comparison, key wrapping/rotation and recovery;
   implement neither unsigned key transfer nor server key custody
3. Implement an authenticated bounded server feed or polling contract, admission
   adapter, explicit opt-in UI/CLI, durable checkpoint storage and local key access
4. Integrate existing encrypted transactions with cancellation/revalidation and
   explicit conflict resolution, including policy and revocation conflicts
5. Expose actual pending/offline/locked/conflict/stale-policy/last-acknowledged
   runtime status and measure healthy-online propagation
6. Run two-device synthetic end-to-end tests for edit/delete/revoke, missed and
   reordered hints, account switch, corrupt snapshots, network failure and locks

Previously copied plaintext and keys cannot be remotely erased. This planner
neither expands existing access nor changes owner-only recovery semantics.

## Synthetic tests

`cargo test --locked --all-features cloud::coordinator --lib` covers every scope
component, default disabled and denial states, bounded/invalid cursors and unknown
versions, 10,000 coalesced hints, duplicate/reordered events, lost notifications,
restart and interrupted attempts, bounded backoff, conflicts and revoked admission
at completion. These are coordinator tests, not two-device runtime tests. Existing
cloud, auth release, sharing and backup suites remain the integration baseline.

## First runtime adapter

The optional [foreground watch](foreground-sync-watch.md) adapter uses this
coordinator with existing manually paired owner vaults and conditional encrypted
snapshot APIs. It adds bounded polling and live session/scope checks. It does not
implement the enrolled-device/ring/background-activation gates described above.
