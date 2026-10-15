# RUG-296: initial rotation approach and simulation

Status: **pre-implementation assessment; dependencies pending**.
[RUG-296](https://linear.app/rankupgames/issue/RUG-296/implement-leaf-certificate-rotation)
is a runtime implementation issue and remains open. This preparation does not
redefine inventory authority, expiration or revocation contracts. It consumes the
pending [inventory](leaf-certificate-inventory.md),
[expiration](leaf-certificate-expiration.md) and
[revocation](leaf-certificate-revocation.md) proposals once approved.

## Source and dependency assessment

The existing [`wispkey_issue_cert` handler](../../src/mcp/mod.rs) issues and exports
leaf material, but does not establish durable leaf ownership, a rotation journal,
or a relying-party activation acknowledgement. The current code therefore cannot
safely retire a predecessor based only on issuance success. Exporting a successor
is not proof that the intended consumer installed and can use it.

Before runtime implementation, upstream owners must supply approved inventory
identities/revisions, eligibility/validity checks and revocation acknowledgement
semantics. The target consumer must define an authenticated, context-bound
activation receipt and rollback/recovery behavior. Rotation consumes these facts;
it cannot substitute claimed JSON fields for them.

## Proposed implementation sequence

1. Authorize the request against authoritative predecessor owner/context and
   inventory revision. Reserve a stable request ID and nonsecret intent digest.
2. Check eligibility and delegate validity/revocation checks. Record a durable
   `prepared` journal entry with immutable predecessor binding.
3. Issue exactly one successor associated with that operation. Store its durable
   inventory identity and journal `issued` before treating delivery as successful.
   Private-key recovery/replay follows the inventory decision; never log keys or
   automatically reissue after an uncertain response.
4. Deliver through the approved channel. Wait for verified activation evidence
   bound to successor identity, owner/context, request and policy revision.
5. Record `activated`, then request predecessor retirement through the revocation
   component. Do not duplicate its authority, propagation or audit mechanisms.
6. Mark `complete` only after the approved retirement enforcement acknowledgement.
   A timeout leaves `retirement_pending`, not a false success or automatic rollback.

Each transition needs durable compare-and-swap and audit atomicity. A competing
request for the same predecessor must fail or join the existing operation according
to an approved concurrency policy. A retry resumes its journal state; altered intent
under the same request ID rejects. Unknown commit outcome must be reconciled by
operation identity, never interpreted as permission to issue another key.

One selected successor may temporarily coexist with a still-valid predecessor.
This overlap is explicit and journaled; approval must set its permitted duration.
Do not claim zero overlap or global retirement until the consumer boundary proves
it. If activation fails, retain predecessor eligibility subject to independent
expiration/revocation; rotation must never extend its validity. If the predecessor
expires during recovery, report loss of availability rather than fail open.

## Executable simulation

Run `python3 -B -m unittest discover -s scripts/tests -p 'test_leaf_rotation_model.py' -v`.
The pure in-memory model covers ineligible requests, issuance failure, activation
failure, mismatched owner/context, early retirement, retirement failure, repeated
transitions and copied-state restart. It tests ordering and safe refusal using
synthetic identifiers. It does not create certificates, persist a journal, verify
activation receipts, enforce TLS trust, or guarantee crash atomicity.

Initial assessment: the ordering invariant is testable without Unix access.
The hard integration risks are authenticated activation acknowledgement, unknown
issuance outcome/key recovery, durable concurrency, and actual revocation scope.
An in-memory transport simulation can later test routing and interrupted responses;
real Unix binding and verifier fixtures remain required before completion.

## Runtime acceptance checklist

- Obtain approved upstream contracts and identify the concrete activation consumer.
- Add transaction failure injection before/after every journal and audit write.
- Test restart at each transition and lost responses without duplicate issuance.
- Race simultaneous rotations with stale inventory and changed authorization.
- Inject expiry/revocation during issuance, delivery, activation and retirement.
- Verify wrong owner/context/request/receipt cannot activate or retire anything.
- Exercise real transport and TLS/consumer bindings, bounded overlap, and measured
  retirement acknowledgement, including partition/reconnect behavior.
- Assert redacted lifecycle evidence and document recovery ownership/runbook.

This assessment supplies an initial approach for review; it does not close the
runtime issue or establish any new credential authority.
