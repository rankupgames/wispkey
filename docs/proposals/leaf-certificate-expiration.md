# RUG-269: leaf expiration enforcement proposal

Status: **proposal, decisions pending**. No runtime enforcement is added.
[RUG-269](https://linear.app/rankupgames/issue/RUG-269/enforce-leaf-certificate-expiration)
remains open. This builds on the [inventory proposal](leaf-certificate-inventory.md)
and its unresolved authenticated owner and actual relying-party boundary.

## Verified starting point

At baseline `398caa488dacf32f7e7cbbc614c227a5d6b7cb44`,
[`src/pki/mod.rs`](../../src/pki/mod.rs) checks issuer CA validity before issuance
and caps requested leaf validity to the issuer lifetime. Its CA check rejects
`not_before > now` and `not_after <= now`. This is not leaf enforcement at a
relying party. Existing external consumers of exported leaf material remain
responsible for their own verification. Inventory timestamps alone cannot enforce
external TLS connections or terminate existing sessions.

## Pending decisions

- E1: identify every actual leaf trust consumer, handshake/session boundary, and
  authenticated binding. No generic helper is complete until all paths use it.
- E2: approve the validity interval and precision. Candidate: integer UTC seconds,
  `not_before <= now < not_after`, matching the current CA check's upper boundary.
  This is a proposed product rule, not a claim about universal TLS library rules.
  Reconcile interoperability before selecting it.
- E3: approve clock-skew allowance and clock health source. Candidate: zero grace;
  unknown/unhealthy time rejects. Never infer healthy time from successful parsing.
  Allowing grace would extend effective acceptance and needs explicit review.
- E4: define long-lived session expiry/revalidation and wall-clock rollback policy.
  Candidate: reject observed rollback, revalidate every trust decision, schedule
  session revalidation no later than expiry. Process-local monotonic tracking alone
  cannot detect rollback across restart; define an independently trusted time floor
  or explicit operator recovery before claiming restart-resistant clock health.
- E5: assign time-policy ownership and safe operator remediation. Changing a clock
  or policy is not an automatic remediation action.

All five decisions are pending. This PR selects no live security policy.

## Candidate integration sequence

1. Resolve the approved owner/context and certificate by stable DER identity.
2. Validate certificate signature, issuer, intended use and identity through the
   chosen verifier. Time checks do not replace these checks or revocation.
3. Obtain one trusted UTC instant and clock-health result for this decision.
4. Validate a well-formed interval and apply the approved precision/skew policy.
5. Re-evaluate even on cache hits. Cache parsed certificate information, never an
   indefinite allow verdict. Bind any bounded verdict to policy and identity.
6. Emit a bounded outcome code and opaque certificate/context identifiers without
   PEM, private keys, credentials, subject/SAN payloads, or raw parser errors.

Candidate failures: `invalid_validity`, `clock_untrusted`, `not_yet_valid`,
`expired`. Their public granularity and internal audit destination need review.
A malformed certificate must not enter this time-only helper as trusted metadata.
Inventory expiry is derived from time, rather than a one-way persisted state that
could accidentally become authoritative after a clock or policy change.

## Executable simulation and assessment

Run `python3 -m unittest discover -s scripts/tests -p 'test_leaf_expiration_model.py' -v`.
The standalone standard-library model deliberately lives outside product imports.
It simulates E2/E3's strict candidate, not certificate parsing, clock trust,
cryptographic verification, kernel transport, or actual TLS integration.

Its matrix covers before/start/inside/end/after, malformed intervals, unhealthy
clock, detected rollback, repeated cache-like decisions, and reconstructed state.
Restart tests require a supplied trusted clock-health assertion; they do not prove
that a machine clock is trustworthy. Errors are fixed codes and synthetic inputs.

Initial assessment: deterministic validity decisions are straightforward to test
without sockets. Binding all real trust paths and restart-resistant clock health
are the principal unresolved risks. Unix transport simulation can exercise routing
and failure propagation later, but cannot prove time authority or external TLS
behavior. No runtime feature is complete from this simulation passing.

## Acceptance gates for implementation

- Approve E1–E5 and inventory owner/context decisions.
- Add actual verifier tests using generated synthetic certificates and injected
  clocks, including parsing precision, CA/leaf boundaries, and malformed encoding.
- Enumerate and test every cache, reconnect, restart, alternate handshake and
  long-lived session path. Prove expiration cannot be bypassed by cache reuse.
- Exercise real supported Unix/Windows transports and the selected TLS library.
- Assert redacted audit/error output and deterministic policy-version behavior.
- Document actual enforcement ownership, clock assumptions, operator recovery,
  and external relying-party limits in the security model before release.
