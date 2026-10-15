# RUG-262: leaf certificate ownership and inventory proposal

Status: **proposal, decisions pending**. This document changes no runtime behavior,
trust policy, vault schema, credential access, or release procedure. It is a
reviewable implementation contract candidate for
[RUG-262](https://linear.app/rankupgames/issue/RUG-262/track-issued-leaf-certificate-ownership-and-inventory),
not evidence that that issue is complete. The implementation tracker remains open.

## Verified starting point

Reviewed against `398caa488dacf32f7e7cbbc614c227a5d6b7cb44`:

- [`handle_tool_issue_cert`](../../src/mcp/mod.rs) opens the local vault, resolves
  the CA credential in the selected project, signs, rechecks CA auth eligibility,
  logs `CertificateIssued`, and returns the certificate and any generated leaf key.
- [`IssuedCertificate`](../../src/pki/mod.rs) already supplies certificate PEM,
  serial, subject/SANs, key algorithm, source, and validity timestamps.
- MCP stdio does not establish a separate authenticated owner principal per call.
  A caller-provided owner name would therefore be a claim, not verified identity.
- The existing issuance audit call is best-effort and is not an atomic durable
  inventory transaction. It cannot be treated as an authoritative ownership table.
- [`security-model.md`](../security-model.md) explicitly documents leaf-key egress
  and the absence of WispKey leaf revocation. No local TLS relying-party verifier
  for these issued leaf certificates has been identified in the reviewed source.

Existing CA authentication/expiry checks must remain intact. They concern use of
CA material; they do not establish downstream leaf ownership or revocation.

## Decisions required before implementation

| ID | Decision | Candidate recommendation | Approval |
| --- | --- | --- | --- |
| O1 | Initial owner model | Start with the local vault owner, explicitly treating trusted local MCP callers as that same owner. Do not claim separate agent identity. | Pending |
| O2 | Future delegated owner | Add an enrolled-instance owner only through an authenticated transport with an approved binding to the issuance operation. Never accept an authoritative owner from MCP JSON arguments. | Pending |
| O3 | Authorized certificate context | Bind resolved project/partition/CA identities and an explicit issuance-policy revision. Decide allowed subject/SAN scope separately; credential host globs do not automatically become CA issuance policy. | Pending |
| O4 | Stable local owner anchor | Choose a persisted vault-owner identifier and restore/clone semantics. A filesystem path, display name, OS username, or mutable project name is not a portable identity. | Pending |
| O5 | Relying-party scope | Name the first actual WispKey trust consumer and its authentication boundary, or explicitly limit the first release to issuance inventory. Inventory alone must not be advertised as external TLS enforcement. | Pending |
| O6 | Duplicate generated-key response | Prefer metadata-only reconciliation after an uncertain response; never automatically reissue or persist a plaintext private key for replay. Decide whether a separately encrypted recovery design is needed. | Pending |
| O7 | Recovery/migration scope | Decide whether encrypted local backup includes inventory and which owner bindings must be re-established after restore. No automatic Cloud propagation. | Pending |

These are recommendations for review, not selected product/security policies.
If O1 is rejected, the owner-authentication mechanism must be approved before
wiring issuance to an authoritative owner. Unsupported/ambiguous principals fail
closed in the future implementation rather than falling back to a claimed name.

## Candidate inventory representation

The following is a synthetic shape, not an accepted storage schema or API:

```json
{
  "schema_version": 1,
  "certificate_id": "synthetic-record-id",
  "leaf_sha256": "<sha256-of-canonical-leaf-DER>",
  "issuer_sha256": "<sha256-of-canonical-issuer-DER>",
  "serial_hex": "01",
  "owner_kind": "local_vault_owner",
  "owner_id": "synthetic-owner-anchor",
  "project_id": "synthetic-project-id",
  "partition_id": "synthetic-partition-id",
  "ca_credential_id": "synthetic-ca-credential-id",
  "issuance_policy_revision": "synthetic-policy-revision",
  "request_id": "synthetic-request-id",
  "request_digest": "<digest-of-canonical-nonsecret-request>",
  "issued_at": "2026-10-15T00:00:00Z",
  "not_before": "2026-10-15T00:00:00Z",
  "not_after": "2026-10-16T00:00:00Z",
  "key_algorithm": "ec-p256",
  "source": "generated",
  "state": "issued",
  "record_revision": 1
}
```

- Canonical DER fingerprint identifies the certificate. Serial alone is not
  globally unique; issuer fingerprint plus serial is a separate uniqueness check.
- Bind stable resolved IDs, not caller-supplied names. A rename must not change
  ownership; deleting/recreating a same-named CA must not inherit old identities.
- `request_id` is scoped to verified owner and issuer. A canonical request digest
  prevents one idempotency key being reused with different subject, SAN, lifetime,
  public key/CSR, or policy context. It must not include any private key.
- Preserve timestamps from parsed signed certificate material and the accepted
  issuance event, not a client-provided clock. Reconciliation must verify these
  against the certificate fingerprint and issuer identity.
- Initial lifecycle states are proposed as `issued` and `quarantined`. `issued`
  means recorded issuance, not that every consumer trusts it. Quarantine marks an
  ambiguous/orphaned record for investigation and confers no use authority.
  Expiry, revocation and successor/predecessor state belong to their own children.
- Subject/SAN values may themselves be sensitive. Decide whether inventory needs
  them, how they are protected, and which operator view may show them. A default
  metadata listing can omit them. Do not include leaf/CA private keys, reusable
  wisp tokens, raw CSRs, or credential plaintext in inventory or audit records.
- A fingerprint does not prove trust by itself. Verify certificate/issuer binding
  and authenticated context before using an inventory result for a trust decision.

## Proposed issuance and consistency sequence

1. Resolve the caller through the approved owner mechanism and resolve immutable
   CA/project/partition identities. Validate the approved issuance policy and its
   revision. Missing context or conflicting owner bindings deny before signing.
2. Reserve the owner/issuer/request-id key and canonical request digest in a
   transaction. Concurrent equivalent requests have one winner; conflicting
   payloads receive a stable conflict result without signing.
3. Sign outside a long-running database write lock, preserving existing CA auth
   rechecks. A reserved request is not yet an issued certificate or use grant.
4. Recheck the relevant authority/revisions and atomically persist inventory,
   reservation outcome, and redacted issuance audit evidence. A failure prevents
   return of the leaf certificate/key. Best-effort audit is insufficient here.
5. Release the result only after durable success and the existing final CA auth
   recheck. A denied final release leaves a traceable issued-but-not-released
   outcome; it must not claim external use occurred.
6. After a lost response, return safe recorded metadata/status for that request.
   Do not repeat the signing operation automatically or promise replay of a
   generated private key that was not retained. O6 must resolve recovery behavior.

The exact transaction/reservation state machine, interruption cleanup and schema
migration need implementation review after the decisions above. No arbitrary
request ID grants access to another owner's inventory or signing result.

## Lookup and trust-consumer contract

Proposed operator operations: list metadata in one approved scope, look up a
certificate fingerprint/issuer+serial, inspect the request outcome, and inspect
quarantined inconsistencies. These are candidate operations, not shipping CLI
commands. Listing never returns leaf keys or CA material.

A future consumer must supply a verified owner/context and certificate identity.
Absent record, ambiguous duplicate, mismatched owner/project/issuer, unknown
schema version, or quarantined state denies the trust decision. Inventory lookup
must not silently mint ownership, enroll an instance, repair a mismatch, or grant
credential access. In-process caches cannot override durable owner/revision
changes. O5 identifies which actual consumer must be wired and tested.

## Required acceptance matrix

| Fixture | Required evidence |
| --- | --- |
| Synthetic generated leaf and CSR leaf | Correct owner/context, DER identity, issuer, timestamps; no private material stored |
| Same name in two projects | Resolution and lookup remain bound to distinct stable IDs |
| Rename, delete/recreate CA, moved credential | No reassignment of prior leaf ownership; stale context rejected |
| Missing owner and caller-supplied forged owner | Deny at the approved trust boundary before release |
| Concurrent duplicate request | One issuance outcome and one inventory/audit commit |
| Reused request ID with different public request | Conflict; no second signing or ambiguous record |
| Inventory or audit write fails | No leaf/key returned; recoverable reservation, no partial authoritative record |
| Restart after reservation/signing/commit | Defined reconciliation at each interruption point; no automatic replay |
| Response dropped after commit | Metadata-only known/unknown-delivery outcome; no false success or reissue |
| Fingerprint/issuer/serial mismatch | Fail closed and surface redacted reconciliation evidence |
| Backup/restore and cloned vault | Follow the approved owner-anchor policy; never silently retain foreign authority |
| Alternate consumer/cache path | Same identity checks; no bypass through a stale cached lookup |
| Secret canaries in all errors/audits | No CA key, leaf key, credential value or reusable capability appears |

Use only disposable local CAs and synthetic identities. Existing PKI/MCP tests
remain regressions; they do not demonstrate the proposed ownership enforcement.
No live credentials, client enrollment, deployment, or real-provider acceptance
is authorized by this document.

## Ownership and sequencing

- RUG-262 owns the inventory schema, ownership binding and reconciliation contract.
- [RUG-269](https://linear.app/rankupgames/issue/RUG-269/enforce-leaf-certificate-expiration)
  owns validity-window checks; inventory timestamps alone do not enforce expiry.
- [RUG-267](https://linear.app/rankupgames/issue/RUG-267/implement-leaf-certificate-revocation-enforcement)
  owns revocation authority/state/propagation.
- [RUG-296](https://linear.app/rankupgames/issue/RUG-296/implement-leaf-certificate-rotation)
  consumes approved inventory, expiry and revocation behavior for rotation.

A maintainer must accept or revise O1–O7, name the implementation/review owner,
and approve the concrete schema/API compatibility plan before runtime work.
This proposal neither assigns people nor closes those issues.
