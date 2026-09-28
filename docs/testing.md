# Feature validation

Run the repository's checks with Python 3.10+, stable Rust (including rustfmt and
clippy), and Node 22/npm for browser tests:

```sh
python scripts/verify.py --all
python scripts/verify.py --suite cli
python scripts/verify.py --suite browser --suite automation
python scripts/verify.py --all --dry-run
```

The runner works from any directory. It stops dependent steps after a failure,
continues other selected suites, and exits nonzero if anything selected fails or
cannot start. A dry run prints **PLANNED**, never **PASSED**. It does not retry
failures. CI supplies job time limits; local runs stream the underlying tools'
output and can be interrupted. The CLI suite runs both default and all-feature
tests because transport behavior depends on the feature set. `--all` includes
CLI, browser/tray web UI, and Python automation; it does not imply every native
platform or live service has been tested.

The browser suite installs locked npm dependencies, builds both extensions and
the tray UI, installs Chromium/Firefox, and runs real browser-engine fixtures.
Linux hosts may first need `npx playwright install --with-deps chromium firefox`
from `browser-extension`. Those system packages can require administrator rights.
Fixtures use synthetic credentials and mocked extension/owner transports. They
do not install a real extension, open an OS approval prompt, or contact a login
website. `crates/wispkey-tray/ui-dist/index.html` is tracked: commit the rebuilt
artifact whenever the tray UI changes.

Additional suites require their own prerequisites:

```sh
# Native tray: OS GUI libraries, plus the Rust and Node prerequisites above.
python scripts/verify.py --suite tray

# Linux/macOS with Docker and Bash (Windows: run inside configured WSL).
# Creates and removes a loopback-only disposable PostgreSQL container.
python scripts/verify.py --suite postgres
```

The native tray build on Debian/Ubuntu needs `libgtk-3-dev`,
`libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, and `libxdo-dev`.
The native tray crate currently has no Rust unit tests: its `cargo test` step
checks test-mode compilation, not GUI behavior. Browser fixtures cover the UI;
the actual system tray, autostart, and OS consent dialogs still need acceptance.
Linux `--all-features` compiles AF_VSOCK but a host
without a usable vsock device cannot establish guest/host connectivity.

## Feature-to-test map

Paths below identify executable tests, including module-local unit tests. This
is a map of behavior covered, not a claim of exhaustive branch coverage. New
features should add a regression at the public interface and update this map.

| Feature / implementation | Automated coverage | Remaining acceptance boundary |
| --- | --- | --- |
| Vault initialization, encryption, schema migration, secure files (`src/core`, `src/secure_files.rs`) | Core/secure-file unit tests; `tests/smoke.rs`, `tests/unlock.rs` | Native credential-store availability differs by OS |
| Unlock TTL, remembered protector, lock/forget | Session/protector unit tests; `tests/unlock.rs`, owner IPC tests | OS credential-store interaction on each release platform |
| Credential add/get/list/remove/rotate and all credential types | Core tests; `tests/cli_contracts.rs`, `tests/projects.rs`, `tests/proxy.rs`, `tests/mcp.rs` | Values remain synthetic in tests; output must never expose plaintext |
| Projects and active-project isolation | `tests/projects.rs`, `tests/cli_contracts.rs`, MCP and proxy tests | Same names in separate projects must stay isolated |
| Partition create/list/assign/delete and scoped lookup | `tests/cli_contracts.rs`, `tests/projects.rs`, bundle tests | Deletion must preserve credentials in personal partition |
| Legacy import and selective env discovery/attach | Migrate unit tests; `tests/env_files.rs`, `tests/cli_contracts.rs` | Attach only values consumed through token substitution or explicit injection |
| Encrypted credential/project/partition sharing | Bundle/sharing unit tests; `tests/bundles.rs` | Passphrase exchange is external to WispKey |
| Full vault backup, inspect, verify, restore | Backup unit tests; `tests/backup.rs` | Restored instances require reenrollment; browser requests excluded |
| HTTP forward/reverse proxy, headers/body/query substitution, CONNECT, management API | Proxy module tests; `tests/proxy.rs`, `tests/proxy_lifecycle.rs` | CONNECT is blind TLS tunneling; real HTTPS substitution uses reverse mode |
| Lifecycle discovery, random port, daemon stop/cleanup | `tests/proxy_lifecycle.rs`, doctor tests | Service managers are deployment-specific |
| TCP/Unix/Firecracker/vsock listener and instance identity | Transport unit tests; `tests/instances_tcp.rs`, `tests/instances_proxy.rs` | AF_VSOCK hardware/guest acceptance requires a capable Linux host |
| Enrollment, scopes, request approval/denial, secret rotation | Core instance tests; `tests/instances_proxy.rs`, `tests/instance_policy_identity.rs` | Fleet enrollment/rotation delivery remains deployment-specific |
| Bootstrap TTL, revocation, max uses, concurrent joins | `tests/bootstrap.rs` and core tests | Real fleet distribution of bootstrap secrets is outside the test runner |
| Policy check/test/explain, host/agent/instance scope | Policy unit tests; `tests/policy.rs`, `tests/instance_policy_identity.rs` | Unknown identity must fail closed; labels cannot authenticate a caller |
| Owner-approved SSH/Kubernetes/PostgreSQL operations | `src/operations` unit/adapter tests; `tests/operation_auth.rs`, `tests/operations.rs`; PostgreSQL Docker suite | Actual destination posture/RBAC/host keys and owner approvals need target-specific acceptance; see #32 below |
| Child-only exec/run/inject and askpass | `tests/exec.rs`, `tests/run.rs`, `tests/inject.rs` | OS/application consumers beyond the fixture children need acceptance |
| Audit export/tail/filter and secret-safe diagnostics | Audit tests; `tests/audit.rs`, `tests/doctor.rs` | Operational log retention/export destinations are outside this repo |
| MCP tools, env sideloads, client config, shell/plugin guards | `tests/mcp.rs`, `tests/env_sideload.rs`, `tests/integrate.rs`, `tests/plugin_hooks.rs` | Actual IDE/client installation is separate from config/stdio contracts |
| CA-held leaf certificate issuance and CSR/key constraints | `src/pki/mod.rs` unit tests plus MCP coverage | Real CA material is never used by tests |
| Website login generation/lifecycle/review dates | Login/core unit tests; `tests/login.rs`, `tests/mcp.rs`, `tests/browser_handoff.rs` | Review dates never auto-delete; signup completion is a human decision |
| Browser native framing, one-use handoff, revision/origin binding | `tests/browser_handoff.rs`, `src/browser_host.rs` tests; extension Node tests | Windows Hello and installed native-host registration require human validation |
| Browser form discovery, navigation, no submission, popup approval gate | `browser-extension/tests/browser/handoff.spec.mjs` in Chromium and Firefox | Browser fixtures mock transport, not human approval |
| Owner IPC authentication, framing, concurrency, log pressure | `tests/owner_ipc.rs`, owner IPC unit tests | Historical timeout monitoring described below |
| Tray UI destination confirmation, generated-login metadata, clearing secrets and IPC errors | `browser-extension/tests/browser/tray.spec.mjs`, native tray build/lint checks | Mocked bridge tests complement actual native tray acceptance |
| Cloud session groundwork, local status/logout, reserved sync commands | `src/cloud/mod.rs` tests, `tests/cli_contracts.rs`, `tests/smoke.rs` | Status is local/unverified; push/pull/sync remain unavailable pending #12 |
| Release assets, installers, Homebrew and packaging | `tests/release_packaging.rs`, `.github/workflows/release.yml` | Signing, registry authentication, and public downloads run in release workflow |
| Validation runner | `scripts/tests/test_verify.py` | Missing tools and failed subprocesses must produce failure, never a false pass |

## Ignored tests and pending backlog

Do not blanket-run `cargo test -- --ignored`. The SSH runtime's ignored child
test is invoked by its parent using a disposable vault; the ignored PostgreSQL
test requires the Docker fixture's explicit settings. Platform-specific ignored
tests must be assessed on the required OS/device. An ignored result is not a pass.

- [Cross-node validation #32](https://github.com/rankupgames/wispkey/issues/32):
  [PR #35](https://github.com/rankupgames/wispkey/pull/35) adds grant expiration,
  scope/concurrency, Kubernetes TLS/posture, and private helper channel tests.
  Loopback servers establish protocol behavior; actual SSH/Kubernetes targets
  still need acceptance by their owner. Use the runtime guide and PR's validation
  checklist with disposable resources; deployment-specific acceptance must use
  that deployment's actual posture and identity configuration.
- [Owner IPC timeout #26](https://github.com/rankupgames/wispkey/issues/26):
  the demonstrated log-drain defect was fixed in PR #30.
  [PR #39](https://github.com/rankupgames/wispkey/pull/39) adds three repeated
  Windows runs under one-CPU contention, bounded failure capture, and scheduled
  monitoring. Its successful runs are evidence for current behavior, not proof
  of the cause of the original failure that lacked diagnostics.
- [Cloud sync #12](https://github.com/rankupgames/wispkey/issues/12): CLI commands
  remain explicit stubs. The separate backend needs conditional revision checks
  and a payload download contract before overwrite-safe synchronization can be
  completed. A successful local session/status test does not validate sync.
- [Optional native CI #28](https://github.com/rankupgames/wispkey/issues/28),
  [promotion #25](https://github.com/rankupgames/wispkey/issues/25), and
  [dependency maintenance #27](https://github.com/rankupgames/wispkey/issues/27)
  have separate PRs #36, #37, and #38. Their automation fixtures are included by
  the `automation` suite after those changes are merged.

## Human acceptance record

Use only disposable accounts/resources and record metadata, never credential
values or native-message payloads. Record commit, OS, browser/version or target
identifier, date, tester, expected/actual outcome, and pass/fail/not-run.

For each installed browser family in a separate human-controlled profile, follow
[`browser-handoff.md`](browser-handoff.md): verify Hello approve and cancel,
navigation and vault lock during approval, login and two-password signup fill,
no automatic submission, no second use of the request, and metadata-only status.
Real approval/cancellation must be performed by the human; fixtures cannot sign
off these rows.

For an owner-provided SSH/Kubernetes destination, follow
[`operation-runtime.md`](operation-runtime.md): check the declared target and
posture, authorize a fresh bounded grant, execute once, verify the intended
destination-side result, reject reuse and changed posture, and inspect sanitized
audit metadata. Record rollback/cleanup of disposable resources. PostgreSQL's
Docker fixture verifies TLS, rotation, revocation, and expiry locally; repeat
destination-specific acceptance where deployment configuration differs.
