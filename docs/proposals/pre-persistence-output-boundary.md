# RUG-432: synthetic pre-persistence boundary assessment

Status: **initial assessment; incident root cause and containment unresolved**.
[RUG-432](https://linear.app/rankupgames/issue/RUG-432/security-investigate-credential-exposure-in-agent-tool-output-and-add)
remains open. No incident records were accessed for this PR. No incident transcript,
credential, fragment, hash or affected-system identifier is included. No retained
history, live credential, permissions or consumer configuration changes.

## Verified source boundary

Baseline: `398caa488dacf32f7e7cbbc614c227a5d6b7cb44`.

- [The operation helper](../../src/operations/helper.rs) runs credential-bearing
  children with private stdin and suppressed stdout/stderr. Its production-path
  fixture verifies argument/environment isolation, structured completion, child
  exit status and disposable replay-store contents.
- [SSH operations](../../src/operations/ssh.rs) include remote stderr suppression
  tests and a bounded helper protocol, not arbitrary command-output delivery.
- [Separate-process handoff tests](../synthetic-operation-handoff.md) exercise
  routing, authentication, grant consumption and synthetic SSH delivery with
  raw/base64 canary checks. Their documented limits remain applicable.
- Audit capability-token redaction is format-specific; it is not proof that every
  bridge, exception, transcript or export removes arbitrary credential values.

These are relevant WispKey boundaries, not a determination of the incident's
emitting component or root cause. Confirm the actual tool-bridge and persistence
owner before modifying that component.

## Concrete regression and simulation scope

This PR extends the real-helper child fixture to emit its received synthetic
marker as raw bytes, base64, percent-encoded bytes, JSON Unicode escapes,
shell-trace-like text and nested JSON error text. Both stdout and stderr receive
flushed chunks crossing arbitrary representation boundaries.

The caller still receives only the bounded helper completion with preserved child
exit status. The fixture scans ready/completion output and every disposable helper
store file for each representation. It tests suppression before those WispKey
surfaces, rather than final-message masking. It does not claim arbitrary encoding
detection: suppression discards the entire untrusted output stream.

Run `cargo test --offline --locked --lib operations::helper::tests:: -- --test-threads=1`.
The fixture uses in-memory duplex protocol and a disposable child process. It does
not need a Unix socket, target server, live credential, external tool bridge or
retained transcript. Hosted platform tests remain required for supported systems.

## Initial approach to the unresolved boundary

1. Have the responsible owner identify the emitting component and exact output
   stores privately. Report component identity, surface categories and safe counts;
   do not copy raw incident material into model context or tickets.
2. Reproduce the confirmed path using a synthetic marker: stdout/stderr, exceptions,
   tracing, partial frames, cancellation, timeouts, serializer failures, previews,
   telemetry and exported/persisted copies.
3. Prefer allowlisted structured results at the component boundary. Keep untrusted
   bytes out of rendering and storage. Fail closed with a fixed code when safe
   output cannot be produced; preserve meaningful exit/error status.
4. Consume the separately reviewed credential-free read proposal in PR #83 if that
   capability is needed. Do not weaken credential-bearing output suppression.
5. Test the actual serializer and storage sink before claiming pre-persistence
   protection. Canary success proves only tested representations and surfaces.
6. Keep exact-record remediation and credential rotation separately approved.
   Scrubbing and regressions do not establish that exposed credentials are safe
   to reuse or that all retained copies have been removed.

## Outstanding acceptance

Confirm component ownership and root-cause path; demonstrate synthetic before/after
behavior at the actual boundary; verify rendering, persistence, telemetry and
exports with safe counts; document stream/error limits and preserved metadata;
obtain exact-target approval for any historical-record or credential action.
Keep containment unresolved until independently verified.

Assessment: WispKey's suppression boundary supports executable synthetic proof;
the unknown tool-bridge/persistence boundary is still an outstanding obligation.
This change strengthens the former without claiming completion of the latter.
