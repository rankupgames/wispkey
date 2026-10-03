# Separate-process synthetic operation handoff

Run the focused Unix fixture with cached dependencies:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test --offline --locked --lib operations::process_handoff_tests:: -- --test-threads=1
```

The parent test is the requester. A separate executor process owns a new encrypted
vault and runs the real identity-required HTTP proxy on an ephemeral IPv4 loopback
port. Another process runs a persistent, pinned SSH protocol fixture. The
requester sends an opaque grant ID and synthetic instance authentication to the
real operation route; only the executor releases the selected value over SSH.
The destination records attempt IDs and delivery counts, never the received value.

The parent concurrently invokes the same grant twice: exactly one succeeds and
only one destination delivery occurs. `join!` and a 150ms destination delay
encourage overlap but do not provide a deterministic overlap barrier.
A later HTTP replay is rejected by the
executor. Separately, an owner-side test probe using the fixture SSH key replays
that attempt directly and is rejected by the
destination fixture's SQLite reservation, before the secret callback runs. This
distinguishes the two boundaries; it does not test destination restart recovery
or substitute for the production restricted helper's replay tests.

Other cases cover an incorrect host pin, incorrect client key, wrong instance
secret, different authenticated requester, cancelled grant, revoked instance,
expired grant and a grant made stale by actual credential-value replacement.
Expiry is seeded in the disposable grant store rather than waiting or changing
the system clock. The destination checks both account and exact public key.

After delivery, adversarial peers send the selected-value canary in stdout,
stderr and malformed protocol JSON, or close without acknowledgement. Every
case returns `outcome_unknown`; replay never releases again. HTTP header names,
header values, bodies, captured child output, audit and destination replay-store
bytes are scanned for raw/base64 selected-value and other specified canaries.
Audit assertions check field names, requester/operation/credential identities,
authorization/start/terminal/denial counts. Internal attempt rows assert selected-value,
provider and old-password release flags; these are not independent release counters.
Persistent destination counters separately verify deliveries and reservations.
Expected totals are seven attempts, five deliveries and one separately
rejected destination replay. Denied preflight requests create no attempts.

Child processes receive a cleared environment, explicit disposable vault
directories and private scratch files. Deadlines and child guards bound execution
and terminate only fixture processes. These checks cover the specified raw and
base64 canaries, not arbitrary encoding or host-level forensic guarantees.
Startup readiness waits are bounded to 60 seconds. Each child has a separate
three-minute lifetime watchdog to allow the full sequence of real authentication
hashes under CI contention. HTTP requests remain bounded to 15 seconds, SSH
operations to 10 seconds, and issued grants to 120 seconds.

This exercises production HTTP routing, instance authentication, grant consumption,
vault release and SSH transport. Grants are seeded through internal test APIs:
it does not simulate or bypass the production CLI's fresh human approval prompt.
Cryptographic keys and instance identities are generated for each fixture.
The master password and selected-value canaries are fixed synthetic constants.
The SSH server is a protocol fixture, not the installed restricted helper or
OpenSSH daemon. The three processes run under one local OS account; they do not
establish host/account isolation or multi-machine acceptance. Use the
[disposable OpenSSH fixture](disposable-cross-node-validation.md) for independent
destination behavior and [runtime acceptance](cross-node-validation.md) for the
remaining deployment checks.

The test does not cover destination restarts, OS-enforced separation, network
partition timing, cancellation after dispatch or host-level output persistence.
Missing acknowledgement is simulated by closing the SSH channel after recording
delivery; it is not a packet-loss or process-crash test. Existing helper/runtime
tests retain their separate coverage and live acceptance gates.
