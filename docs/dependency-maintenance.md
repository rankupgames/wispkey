# Dependency maintenance

`Scheduled dependency audit` runs daily at 07:17 UTC and via manual dispatch.
It audits the current committed `Cargo.lock` on **main, development, and release**,
including workspace/optional dependencies present in that lockfile. Deleted or
unavailable maintained branches fail checkout instead of silently losing coverage.
This RustSec monitor does not cover npm dependencies or deployed artifacts.

Every job fetches a new advisory database with pinned cargo-audit 0.22.2, runs
outside branch-local configuration, and has a bounded timeout. Blocking
advisories fail the job and the Actions summary lists dependency/version,
RustSec ID, and patched versions (or the need to replace/mitigate). Informational
warnings are separate. Database/tool/report failures also fail; no result is
treated as clean after a reporting error. Raw reports, source URLs, and tool
stderr are not published.

Repository maintainers own failed-run triage. Enable Actions notifications for
this repository and inspect the named branch job on failure; GitHub's scheduled
workflow notification recipient depends on the schedule actor. Maintain this
subscription when maintainership or the schedule changes. The workflow creates
no issues, comments, or external messages, so recurring findings cannot generate
duplicate public reports. Maintain one reviewed remediation PR per affected
dependency/advisory, linking the existing public RustSec advisory. Search open
PRs first. Application-specific vulnerabilities still go privately to
security@rankupgames.com as required by CONTRIBUTING.md.

Prepare minimal updates on a branch from the affected maintained branch:

```sh
cargo tree -i affected-crate
cargo update -p affected-crate --precise PATCHED_VERSION
git diff -- Cargo.toml Cargo.lock
cargo audit
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

If the manifest excludes the patched version, update only that constraint and
review its lockfile changes. Open a PR and require existing CI before merging;
there is no auto-merge. Apply equivalent reviewed updates to other affected
maintained branches. Re-run the scheduled workflow after merging to verify all
three graphs. Never downgrade a real dependency to test the monitor.

No advisory exception or automatic suppression is configured. Any future
exception requires a separate reviewed change with advisory ID, affected
versions, rationale, compensating controls, owner, and expiry. Informational
warnings do not constitute approved exceptions to blocking advisories.

## Stable refresh constraints (October 2026)

The compatible refresh replaces yanked `chacha20 0.10.1` with `0.10.2`.
The [upstream fix](https://github.com/RustCrypto/stream-ciphers/pull/580)
corrects CPU-intrinsic selection; no application cipher, key derivation, or
stored format is changed. The refresh also updates compatible HTTP, certificate,
CLI, UUID, error, and browser-launch dependencies within existing constraints.
Existing proxy, certificate, bundle/backup, login, and owner-IPC regression suites
and the native three-platform CI matrix remain required before merging.

`toml 0.8.2` cannot currently resolve to `0.8.23`: the optional Linux webview
graph contains `glib-macros 0.18.5 -> proc-macro-crate 2.0.2`, which pins
`toml_datetime =0.6.3`, while newer TOML 0.8 requires `^0.6.11`. Address this with
the coordinated native/TOML migration; do not force overrides or drop platform
features to make a patch-only update resolve.

Major migrations require separate review of behavior and compatibility:

- Reqwest 0.13 changes TLS-provider and form/query feature selection. Preserve
  the explicit ring provider, trust roots, proxy behavior, and redirect policy.
- Keyring 4 splits platform stores. Prove existing remembered protectors remain
  recoverable and forgetting them still removes the correct OS entry.
- Native tao/tray-icon/wry upgrades need Linux GTK/WebKit, macOS and Windows
  builds; recheck the remaining RustSec warnings rather than suppressing them.
- `windows 0.62.2` requires `windows-future 0.3.2`; `windows-future 0.100.0`
  changes its core types and cannot be substituted independently in consent code.
- Storage, Argon2, TOML and encoding major updates need existing-file and
  encrypted-bundle compatibility evidence, beyond successful compilation.

CI follows stable Rust; retain the declared minimum until a tested migration
requires raising it. Do not introduce prereleases as a substitute for a stable
upgrade. Existing upstream constraints (including russh's ssh-key release
candidate) need an upstream-compatible replacement, not an arbitrary downgrade.

Offline fixtures exercise failure/reporting without changing dependencies:

```sh
python3 -B -m unittest discover -s scripts/tests -p 'test_audit_dependencies.py'
```
