# Dependency maintenance

`Scheduled dependency audit` runs daily at 07:17 UTC and via manual dispatch.
It audits the current committed `Cargo.lock` on **main, development, and release**,
including workspace/optional dependencies present in that lockfile. Deleted or
unavailable maintained branches fail checkout instead of silently losing coverage.
This RustSec monitor does not cover npm dependencies or deployed artifacts.

Every job fetches a new advisory database with pinned cargo-audit 0.22.1, runs
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

Offline fixtures exercise failure/reporting without changing dependencies:

```sh
python3 -B -m unittest discover -s scripts/tests -p 'test_audit_dependencies.py'
```
