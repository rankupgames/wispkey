# Windows owner IPC reliability validation

Issue [#26](https://github.com/rankupgames/wispkey/issues/26) records an
intermittent hosted Windows response timeout. [PR #30](https://github.com/rankupgames/wispkey/pull/30)
subsequently reproduced a logging stall: the test harness captured stderr
without draining it, and filling the pipe blocked the server before its reply.
That fix continuously drains a bounded capture and adds log-pressure and
concurrent-client regressions. It preserves five-second connection/read
deadlines and bounds request writes too. Phase timings omit request values.

The original failure predates those diagnostics. The logging reproduction is
evidence of a real fixed cause, not proof that every historical timeout shared
that cause. Do not close #26 solely because an unchanged rerun passes.

Run the repeatable contention check from a separate Windows PowerShell process:

```powershell
powershell -NoProfile -File scripts/test-owner-ipc-contention.ps1
```

It compiles first, restricts its own process to one available CPU, and launches
the existing owner IPC suite with fourteen test threads. Windows children inherit
that affinity, so vault initialization and the actual servers share the CPU.
The suite still uses temporary vaults and synthetic values and retains all
authentication, destination-confirmation, redaction, log-pressure, and separate
four-client concurrency assertions. It runs three times, stopping on the first
failure; no failed test is retried. Each run is bounded at 180 seconds, with the
test process tree terminated on timeout and affinity restored on exit.

CI runs this on relevant PRs, weekly, and via manual dispatch. This supplements
the normal Linux/macOS/Windows suite. The summary records per-run duration and
exit status. Readiness and failure messages distinguish startup from request
handling and connection/write/read phases. Do not increase production deadlines
to make a stress run pass. If a timeout recurs, retain the exact commit, runner,
test name and phase timings; compare them with the log-pressure reproduction
before attributing a cause.

## Recorded local run: 2026-09-28

On Windows with Rust 1.96.0 and the committed lockfile, all 13 tests passed in
each of three consecutive one-CPU runs with fourteen test threads. Script
durations were 52.44, 50.07, and 50.86 seconds, all exit 0. The running harness
affinity was also observed as `1`. These results validate the current harness
under the stated contention; they do not identify the original hosted timeout.
