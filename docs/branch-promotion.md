# Branch promotion

The weekly `Promote & Backmerge` workflow reconciles `development → release →
main → development` in order. Manual dispatch defaults to a dry run. It uses PRs
for every destination, including unprotected branches, so no direct merge or
rule bypass is needed. Required reviews and checks still govern merging.

An identical comparison, or a source already behind its destination with zero
commits ahead, is a **verified no-op**. Otherwise the workflow creates or reuses
one open PR for that exact source/destination pair and reports **pending PR**.
Subsequent steps are **skipped** until the prior source is integrated. Merge the
PR with a merge commit to preserve branch ancestry, then dispatch again or wait
for the next schedule. Squash/rebase merges do not preserve this ancestry and
can cause the same commits to be proposed again.

The automation never reports **merged** itself because it does not perform a
merge. A later run verifies ancestry independently. API, permission, conflict,
and transport failures produce **failed**, a nonzero job result, and skipped
dependent steps. Errors expose only status codes and fixed diagnostics, never
arbitrary API response bodies. Inspect the PR for conflicts and required checks.

Repository settings must allow GitHub Actions to create pull requests. The job
needs read access to contents and write access to pull requests. GitHub may
require a maintainer to approve workflow runs for a PR created with
`GITHUB_TOKEN`; review and approve these checks before merging. See GitHub's
[workflow trigger documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
Do not weaken branch protection to make reconciliation pass. CI includes
`release` as a PR base so promotion PRs receive the same validation.

Fixture tests do not contact GitHub or mutate branches:

```sh
python3 -B -m unittest discover -s scripts/tests -p 'test_promote.py'
```

They cover ahead/diverged and already-integrated histories, PR creation/reuse,
dependent-step gating, dry runs, protected-operation rejection, permission and
service failures, malformed responses, and bounded transport timeouts.
