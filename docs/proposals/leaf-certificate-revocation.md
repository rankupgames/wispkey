# RUG-267: leaf revocation enforcement proposal

Status: **proposal, decisions pending**; no runtime revocation is implemented.
[RUG-267](https://linear.app/rankupgames/issue/RUG-267/implement-leaf-certificate-revocation-enforcement)
remains open. Depends on the [inventory proposal](leaf-certificate-inventory.md).
Cloud account/session access revocation is a separate responsibility (RUG-297).

## Source assessment

At baseline `398caa488dacf32f7e7cbbc614c227a5d6b7cb44`,
[the security model](../security-model.md) explicitly says exported leaves are not
revoked by WispKey. Existing credential/session eligibility checks are not leaf
revocation. No authoritative leaf revocation store or actual leaf relying-party
consumer has been identified. A local database flag cannot revoke a certificate
already accepted by an external service without that service's participation.

## Pending decisions

- R1: choose the authenticated revocation authority and scope, consuming approved
  owner/project/CA identities. Never trust a caller-supplied owner field.
- R2: identify actual relying parties and enforcement boundary, including existing
  sessions. Candidate: every new trust decision; existing-session termination
  requires a separately specified integration and acknowledgement.
- R3: choose authoritative durable storage, transaction semantics, monotonic
  revision source and restore behavior. Candidate: append-only revoked tombstones;
  no un-revoke operation. Backup restore must not silently resurrect a leaf.
- R4: approve propagation protocol, maximum freshness and clock assumptions.
  Candidate: reject unknown, missing, stale, future-dated or unavailable state.
  Do not accept an unsigned remotely supplied revision as authoritative.
- R5: specify concurrent requests and acknowledgement. Candidate: stable request
  key plus certificate identity/context digest; repeat same request returns its
  existing result, conflicting reuse rejects. State and audit commit atomically.
- R6: assign recovery owner and bounded operational behavior. Revocation failure
  must not fall back to allowing access; recovery needs a fresh authenticated
  snapshot and must preserve revocation tombstones/revision high-water marks.

These recommendations are review items, not approved security policy.

## Candidate lifecycle and integration

An authorized revoke transaction validates the inventory binding and expected
revision, persists a tombstone plus redacted audit event, and returns the durable
revision. A delivery acknowledgement is separate from a relying party's actual
enforcement acknowledgement. Do not report global completion from local commit.

A consumer obtains an authenticated snapshot bound to authority, certificate,
context and revision. It checks freshness using approved time semantics and
rejects rollback below its durable high-water mark. Unknown certificate identity
is not equivalent to active. Parsed identity may be cached, but allow decisions
must be re-evaluated. A known tombstone remains denied even if later delivery fails.

Partition loss, cache eviction, restart or restored old state must not yield a new
allow verdict. The high-water mark itself needs rollback-resistant persistence or
an authoritative online recheck; a process-local integer cannot establish that.
The store and authenticated transport remain prerequisites, not model features.

Safe evidence contains opaque certificate/request/context identifiers, revision,
fixed result codes, commit time, and separately tracked propagation boundary.
It excludes private keys, credentials, PEM and unbounded subject/reason payloads.

## Simulation and initial assessment

Run `python3 -B -m unittest discover -s scripts/tests -p 'test_leaf_revocation_model.py' -v`.
The test-only model uses synthetic records, injected time, and explicit authenticated
snapshot/authority assumptions. It covers active/revoked/unknown/unavailable/stale,
future observations, revision rollback, idempotent repeats, conflicting requests,
cache reuse, and reconstruction after restart. It neither signs nor propagates data.

Assessment: state-machine and negative-path behavior can be simulated without a
Unix socket. Actual authority binding, durable atomicity, rollback protection,
transport partition behavior and external verifier enforcement remain unproven.
A green model cannot establish those security properties.

## Implementation acceptance gates

Approve R1–R6 and inventory decisions, identify the actual trust consumers, then:

- Test authenticated authority/context mismatch and forged snapshot rejection.
- Inject transaction/crash failures around state plus audit commit.
- Test real transport partitions, delayed/out-of-order delivery, revoked cache
  entries, alternate trust paths, restart and restored stale backups.
- Measure the agreed propagation boundary and existing-session behavior.
- Verify negative-path audit redaction and bounded recovery without fail-open.
- Update the security model/runbook with measured limits before release.
