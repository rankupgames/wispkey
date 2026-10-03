# Pinned Actions runtime migration

The October 2026 update moves these Actions from their Node 20 runtime to
Node 24. Official release tags were resolved through GitHub's commit API and
the `action.yml` and migration notes were reviewed at those immutable commits.
Application Node versions are separate from the Action runtime.

| Action | Previous | Stable release | Pinned commit |
| --- | --- | --- | --- |
| actions/checkout | 4.2.2 | [7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-node | 4.4.0 | [7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0) | `820762786026740c76f36085b0efc47a31fe5020` |
| actions/upload-artifact | 4.6.2 | [7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1) | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| actions/download-artifact | 4.3.0 | [8.0.1](https://github.com/actions/download-artifact/releases/tag/v8.0.1) | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| Swatinem/rust-cache | 2.8.1 | [2.9.2](https://github.com/Swatinem/rust-cache/releases/tag/v2.9.2) | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` |

## Compatibility and trust boundaries

[Checkout](https://github.com/actions/checkout/blob/v7.0.1/README.md) now
persists credentials in a runner-temporary file instead of directly in Git
configuration. Existing persistence defaults are retained, including the
explicit `persist-credentials: false` for audited branch content. The new
unsafe fork checkout opt-in is not enabled. Existing `pull_request` behavior
and merge-ref selection remain unchanged; no `pull_request_target` or
`workflow_run` trigger is introduced. Hosted runners satisfy the Node 24
minimum runner requirement (2.327.1); future container-based authenticated Git
use must also meet checkout's 2.329.0 requirement.

[Setup-node](https://github.com/actions/setup-node/blob/v7.0.0/README.md) can
automatically cache npm based on package metadata. Explicit
`package-manager-cache: false` preserves the existing uncached behavior.
[Rust-cache](https://github.com/Swatinem/rust-cache/blob/v2.9.2/README.md)
retains the existing shared keys, provider, target/workspace selection,
job/environment key components and successful-run save behavior. Its new
key-component switches remain enabled by default; no cross-job or cross-branch
cache scope is broadened.

[Upload-artifact](https://github.com/actions/upload-artifact/blob/v7.0.1/README.md)
retains zipped uploads (`archive: true`), hidden-file exclusion, artifact names,
paths, missing-file behavior, repository-default retention and overwrite rules.
Direct unarchived uploads are not enabled. The
[downloader](https://github.com/actions/download-artifact/blob/v8.0.1/README.md)
keeps extraction enabled and preserves existing name/pattern/merge behavior.
No downloads select artifact IDs, whose directory behavior changed in v5.
The new digest mismatch default fails closed instead of warning. Existing
archive checksums and signed release metadata remain additional release gates.

Workflow permissions, secret bindings, schedules, event filters, publication
conditions and job dependencies are unchanged. Release/signing/promotion
actions outside this five-Action group retain their existing reviewed pins.
This PR does not execute a release or deployment.

## Regression evidence

Run `python3 -B -m unittest discover -s scripts/tests -p 'test_*.py'`.
`workflow_boundaries.json` records the reviewed event, permission, environment,
job-gate, checkout, cache and artifact-input contract from main `e4e1c03`.
Its only added artifact consumer downloads the existing extension artifact
back into its CI job for a byte/path comparison. Review any future contract
change explicitly; do not regenerate the fixture merely to silence a failure.
The fixtures also reject unpinned Actions, unsafe fork triggers and implicit
npm caches. They are focused contract checks, not a complete YAML parser.

`verify_artifact_tree.py` compares file paths and SHA-256 content after hosted
upload/download. It fails for missing, extra, wrapped, changed, empty or linked
content; ZIP permission normalization is deliberately outside this comparison.
It creates no additional artifact and changes no retention setting. Local
negative fixtures cover missing/extra/wrapped/truncated trees and setup errors.

Validate syntax/expressions separately with `actionlint` (local review used
official 1.7.12 with its published SHA-256 verified). The full hosted CI must
pass on the published head, including the real artifact round trip and all
three native platforms. Release-only signing/publication is not exercised by
PR CI; those paths retain their existing tag/manual gates and require normal
release acceptance before publishing.
