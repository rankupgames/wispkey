# Credential-free named read operations: review proposal

Status: **not approved or implemented**. This document addresses the remaining
read-operation review in [RUG-447](https://linear.app/rankupgames/issue/RUG-447/enforce-named-ssh-and-sudo-credential-operations).
It does not amend the approved [cross-node contract](../cross-node-operations.md).
The accompanying tests lock down current denial behavior. They do not test a
working read-operation implementation.

## Why a catalog alone is insufficient

At baseline `538358dcb5b2cfb69805c4f48ce013286f2d926b`:

- `src/operations/catalog.rs` accepts catalog versions 1 and 2 and requires a
  canonical, non-nil credential UUID. `ssh-helper` is the only SSH kind.
- `src/core/operation_grants.rs` binds authorization and reservation to the
  selected credential and its revision. Its grant table requires non-null
  credential reference/revision, and grant/attempt status requires a string
  credential reference. Credential-free authority cannot be represented by
  silently leaving a field empty or inserting a sentinel UUID.
- `src/operations/runtime.rs` requires a version-2 instance-bound catalog,
  reserves the grant, then supplies the adapter a deferred decryption callback.
- `src/operations/ssh.rs` verifies the pinned host/account, exchanges protocol-v1
  hello/ready, then invokes that callback and delivers the selected credential.
  Completion accepts only a fixed outcome, count and validated exit code.
- `src/operations/helper.rs` waits for delivery, passes the selected credential
  on private stdin to the fixed program, and discards stdout/stderr.
- `operation check` can validate metadata without a vault or SSH identity file.
  Its `execution_available` flag is capability discovery, not authentication,
  a grant, or proof of connectivity.

A catalog entry is therefore neither an authorization workaround nor a safe
way to retrieve arbitrary shell output. Existing `exec --askpass` is a different
owner-only plaintext-egress surface and must not be substituted for this path.

## Decisions the maintainer must approve before implementation

1. **One initial operation and its result.** Name the operation, the fact it
   reports, and an exact finite result schema. Identify which fields may be
   returned to its authenticated requester. A possible narrow starting point is
   a fixed service-state enum; this is an example for review, not a selected
   operation. Do not add generic strings, arbitrary JSON, logs, files, command
   output, hostname inventories or caller-defined result schemas by default.
2. **Read authorization and lifecycle.** Decide whether read grants remain
   bounded by the current unlocked owner session, project, enrolled instance
   generation and fresh interactive approval. Recommended: preserve those
   requirements and one-use/cancellation/concurrency semantics. Removing the
   selected credential also removes credential-revision/revocation invalidation;
   explicitly replace that binding with the reviewed read-policy revision.
   Merely deleting a credential check is not an equivalent authorization model.
3. **Version and compatibility boundary.** Approve a distinct versioned catalog
   kind and helper protocol, plus a grant/storage migration and typed status
   result. Existing v1/v2 entries and helper-v1 delivery semantics must remain
   unchanged. Decide how old binaries fail closed against the new persisted
   state; the vault schema guard must prevent downgrade misinterpretation.
4. **Result availability and retention.** Decide whether validated results are
   one-time responses or persisted for authenticated status retrieval. Specify
   expiry and behavior after session lock, requester rotation/revocation,
   policy changes, cancellation, terminal-write failure and backup/restore.
   Recommended initial scope: no raw output persistence; keep the approved
   eight-field audit schema unchanged. A null audit credential reference for a
   read is a proposed new meaning and requires explicit review.
5. **Destination policy.** Separately approve the exact requester, executor,
   destination IP/account, Ed25519 pin, dedicated SSH identity, helper, program,
   static arguments and privileges before any deployment. "Credential-free"
   means no selected vault credential is delivered. SSH authentication still
   uses a credential and does not become anonymous or permissionless.

Contract owner: Miguel Lopez as maintainer. A destination owner must also review
any concrete helper/program and deployment policy. Approval of this proposal
would authorize only the agreed implementation contract, not installing a
helper, enrolling an instance, creating persistent access or running it live.

## Proposed implementation boundaries after approval

### Catalog and grants

Represent delivery and read operations with an explicit discriminant rather
than an optional credential that accidentally disables checks on delivery.
Reject unknown kinds/fields and cross-mode fields. Bind the exact operation,
result schema, destination and helper policy into the reviewed catalog digest.
Never infer read authority from the operation name, a missing credential, an
existing proxy scope, a management token, or a caller-provided "read-only" flag.

Retain current-instance authentication, fresh owner approval, earliest bounded
expiry, durable atomic start audit/reservation, single use, per-target and
per-operation concurrency, cancellation and fail-closed terminal persistence.
No automatic retry after an uncertain result. Existing credential-delivery
entries continue to bind credential eligibility and revisions at every release.

### Helper and SSH transport

Use an explicit versioned read handshake with no `deliver` phase, no decryption
callback, no selected-credential bytes and no empty-value delivery convention.
Keep pin verification before helper exchange, fixed account and fixed helper
path, no terminal, agent, forwarding, user SSH config, caller shell text or
caller parameters. A delivery-only helper must reject a read handshake, and a
read-only helper must reject any delivery frame.

The helper remains responsible for a reviewed fixed child program, a cleared
environment, closed/non-secret stdin, bounded runtime and cancellation of its
process group, and durable attempt replay protection. Calling an operation
"read" does not prove it is side-effect free: the destination owner must verify
program behavior and filesystem/network authority. No broad sudo grant follows
from this proposal.

### Typed results and output suppression

The helper must collect only bounded private bytes for the approved result
protocol; never inherit stdout/stderr into a user-visible terminal. Validate the
whole response and its successful completion before releasing any result.
Enforce a byte cap before allocation growth, total-stream cap, field/count/range
bounds and exact framing. Return a fixed safe error for malformed, duplicate,
unknown, excessive, truncated, mismatched-attempt, unsupported-version or
unexpected-stream data. Never return parser errors containing input.

Prefer a concrete Rust enum/struct with deny-unknown-fields and bounded values
for each approved result. Do not use a generic `serde_json::Value`, arbitrary
strings, caller-selected JSON schema or redaction as the release boundary.
An enum/counter is not proof a compromised target cannot encode information;
the trusted-runner/target-root limitation remains. Arbitrary numbers are also
information-bearing and need operation-specific ranges and purpose.

Do not append results to the eight-field audit. If approved for later retrieval,
store only fully validated typed data, bind it to the attempt and requester,
and apply the explicitly approved retention policy. Preserve child exit status
separately from helper status. Lost acknowledgement, timeout, cancellation or
failed terminal persistence must not expose an unconfirmed result.

## Required synthetic verification for the future implementation

- Positive fixture: exact pinned target, requester, one-use grant, reviewed read
  policy, successful child completion and only the selected typed result.
- No selected credential exists in the fixture vault. Assert no credential
  decrypt/delivery callback is invoked and no delivery frame is transmitted.
- Existing delivery catalogs/grants/helper-v1 tests still pass; missing/empty/
  sentinel credentials in those modes remain denied. Old catalogs cannot opt
  into output through extra fields. Old binaries reject the new schema.
- Wrong requester/generation/session, target/account/pin, changed catalog/result
  policy, expired/revoked authority, duplicate/concurrent attempts and required
  audit-write failures deny without execution or result release.
- Byte-at-a-time and arbitrary chunk boundaries; cap minus one, exact cap and
  cap plus one; cumulative overflow, no newline, multiple/trailing frames,
  duplicate/unknown keys, wrong types/ranges/version/attempt and invalid Unicode.
- Synthetic canaries in stdout, stderr, tracing, errors, escaped/encoded and
  partial output never reach returned status, logs, audits, saved results or
  backups. Assertions report failure without echoing rejected input.
- Cancellation before connection, after handshake, during child execution and
  after result validation; connection/runtime timeout, nonzero exit, signal,
  lost acknowledgement and persistence failure. No success based on partial
  output, no reuse of a reserved grant and no automatic replay.
- Test approved result-retention/expiry behavior and cross-mode/downgrade
  rejection through public CLI/API boundaries, not only internal parsers.

## What this change verifies now

`tests/operations.rs` adds a positive v2 metadata-preflight case without a vault
and a rejection matrix for v1/v2 missing, empty, sentinel and nil credentials,
proposed `ssh-read`, credential-free/output flags, result sections and catalog
v3. It verifies failure responses do not echo the synthetic canary or catalog
path, the source catalog remains unchanged, and no vault state is created.
These tests do not prove live connectivity, grant issuance, remote read results
or a new protocol implementation.

[RUG-432 containment](https://linear.app/rankupgames/issue/RUG-432/security-investigate-credential-exposure-in-agent-tool-output-and-add)
remains in force. No affected credential or raw incident history is used.
Destination setup, actual approved target/result evidence and broader RUG-447
acceptance remain open. Nothing here activates an operation catalog, changes
live access, deploys, installs, publishes a release or merges code.
