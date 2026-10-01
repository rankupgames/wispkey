# Owner IPC contention diagnostics

This diagnostic patch does not change pipe lifetimes, handler scheduling,
timeouts, retries, cryptography, or request/response behavior. The existing
Windows stress workflow still runs three iterations with one CPU and fourteen
test threads, stopping on the first failure. Every result remains evidence;
a successful iteration does not resolve an intermittent failure.

`WISPKEY_OWNER_IPC_DIAGNOSTICS=1` enables Windows server stderr timing records.
The integration fixture enables this only in its disposable server children.
Each record contains a PID, server-local connection sequence, fixed method/phase
identifier and elapsed milliseconds from the server diagnostic clock. It never
contains request IDs, parameters, response bodies, values, paths or error text.
Unknown methods become `unknown`; phases before request parsing use `pending`.

Phases distinguish connect wait/completion, read wait/completion, handler
start/completion, write start/acceptance, and readiness of the next instance.
Read-empty and malformed-request paths also have fixed identifiers. A missing
completion identifies the last observed boundary, not by itself the cause.
Elapsed times include scheduling delay and are not CPU-time measurements.

`write_accepted` deliberately does not claim OS completion or peer receipt:
the locked Tokio/Mio named-pipe implementation can enqueue an overlapped write
and return its length, and its async flush is a no-op. No blocking flush or
runtime scheduling change is introduced to compensate.

The fixture continuously drains stderr. Its failure reporter separately parses
only the timing grammar for that child PID, with a 256-byte maximum line and
128-record tail. Oversized, malformed, foreign-PID and unknown-label records
are discarded. It prints the safe snapshot before killing/reaping the child,
then only newly drained safe events. Existing raw request logs remain bounded
and available solely for the existing redaction assertions; they are not printed
by the new failure reporter.

Tests: `cargo test --locked --test owner_ipc_diagnostics --test owner_ipc`.
The diagnostic target tests canary exclusion, foreign/unknown field rejection,
stream fragmentation, oversized-line recovery, retained-tail bounds and
incremental capture after cleanup. On Windows a deliberately nonresponding pipe
peer also verifies the original five-second response deadline and fixed-method
timeout diagnostics, including an unknown malicious method label.

Inspect all failed and successful stress iterations. Compare PID/connection
sequences within a server; clocks across separate processes are not synchronized.
Add more fine-grained handler diagnostics only if these boundaries justify it.
Parent review is required before changing runtime behavior or treating any
timeout as expected. Native browser approval and PR57 are separate.
