# macOS Apple Silicon staging artifact

This manually built test bundle contains the CLI, browser native host, matching
unpacked Chromium/Firefox extensions and the existing Mac registration script.
It is not an installer, a published release, or an Apple-notarized distribution.
No experimental features are compiled; Cloud receiver activation remains absent.

Dispatch `macos-staging-artifact.yml` on the reviewed ref with `expected_commit`
set to its full lowercase 40-character commit. The build refuses a moved ref.
There is no publish, deployment, installation or credential input. All source is
checked out by the run's immutable SHA with checkout credentials disabled.
Pinned actions/tooling match the existing repository workflows. Mac runners must
be native ARM64; a runner architecture change fails closed.

The producer checks Cargo's exact empty feature set and release executable
records, Mach-O target, extension/source equality and a clean tracked checkout.
`BUILD.json` records commit, target, features, lockfile hash and every payload
hash. The separate validation job checks bounded exact ZIP inventory, regular
files only, source content, strict extension permissions and executable headers
before writing only fixed paths in a disposable directory. CLI help/version,
missing receiver/watch commands and locked native-host denial precede a synthetic
login/encrypted-backup/restore round trip. The child environment starts empty and
uses only disposable HOME/vault paths and synthetic passphrases. No real native
approval, browser registration, credential release or Cloud connection is tested.

Unvalidated archives last one day. The verified ZIP, smoke report and canonical
LF `SHA256SUMS.txt` last seven days. Only runs on `refs/heads/main` receive GitHub
build-provenance attestation after validation. Branch artifacts are unattested
review candidates. The provenance job alone gets `id-token: write` and
`attestations: write`; other jobs have only `contents: read`. It uses ephemeral
GitHub OIDC and writes attestation metadata, without user OAuth credentials or
Apple signing secrets. There are no publication jobs, release tags or deployments.

Before transfer, verify the actual expiration, archive/report checksums and
`gh attestation verify <archive> --repo rankupgames/wispkey`; require the approved
source and this workflow identity. A version string or BUILD.json alone is not
authenticated provenance. Verification needs the matching source checkout:

```sh
python3 -B scripts/macos_staging_artifact.py verify \
  --directory /private/staging-download --commit FULL_REVIEWED_COMMIT
```

Extraction/verification does not authorize running or installation. Keep the
bundle outside PATH until the owner approves an exact setup plan. The existing
installer defaults to a read-only plan and requires an explicit host path and
the actual unpacked Chromium extension ID. Its explicit `--install` writes the
per-user manifest; neither packaging nor smoke invokes it. Do not change browser
security settings, ACLs, Gatekeeper or biometric enrollment to pass a test.

An approved setup must name the human-controlled browser profile, protected host
path, exact native manifest/extension ID, and disposable acceptance origin.
Touch ID, installed extension/native pipe, cancellation, navigation and no-submit
behavior need human acceptance; see `docs/macos-browser-approval.md`. Never expose
that profile's DOM or session store to an agent to work around owner approval.
Rollback removes only the specifically installed extension/manifest and staged
files after coordination; it does not downgrade an upgraded vault. Before any
real-vault open, coordinate consumers and verify a pre-upgrade encrypted backup.
Schema migration is one-way; retain the old binary and backup for recovery.
