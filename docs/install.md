# Install and Verify WispKey

WispKey ships signed, checksummed binaries for Linux, macOS, and Windows. Prefer a GitHub Release, Homebrew, or `cargo install` over an unsigned copy.

## Install

### Homebrew (macOS and Linux)

```bash
tmp_dir="$(mktemp -d)"
tap_name="local/wispkey-install-$$"
cleanup() {
  brew untap "$tap_name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

formula_url="https://github.com/rankupgames/wispkey/releases/latest/download/wispkey.rb"
brew tap-new --no-git "$tap_name"
tap_dir="$(brew --repository "$tap_name")"
curl --fail --location --silent --show-error "$formula_url" --output "$tmp_dir/wispkey.rb"
cp "$tmp_dir/wispkey.rb" "$tap_dir/Formula/wispkey.rb"
HOMEBREW_NO_AUTO_UPDATE=1 brew install --formula "$tap_name/wispkey"
wispkey --version
```

Homebrew's current formula loader does not accept arbitrary remote formula URLs. This temporary-tap flow installs the platform-matching signed archive from GitHub Releases and checks its SHA-256 digest before extracting.

### Cargo (all supported targets)

```bash
cargo install wispkey --locked
```

For a non-dry-run tag operation, the release workflow checks `CARGO_REGISTRY_TOKEN` before any external publication, then verifies this path with a fresh `cargo install` from crates.io after publication.

### GitHub Release archives

Download the archive for your platform from [Releases](https://github.com/rankupgames/wispkey/releases):

| Platform | Archive |
|----------|---------|
| Linux x64 | `wispkey-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `wispkey-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `wispkey-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `wispkey-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `wispkey-x86_64-pc-windows-msvc.zip` |

Each archive contains `wispkey` (or `wispkey.exe`), `LICENSE`, `README.md`, and a `VERSION` file with the crate version and source commit.

## Verify checksums

Download `SHA256SUMS.txt` from the same release, then verify the archive you fetched:

```bash
# GNU coreutils
sha256sum -c SHA256SUMS.txt --ignore-missing

# macOS: set this to the archive you downloaded.
archive="wispkey-aarch64-apple-darwin.tar.gz"
entry="$(
  awk -v file="$archive" '$2 == file { print; count++ } END { if (count != 1) exit 1 }' SHA256SUMS.txt
)" || {
  echo "missing or duplicate checksum entry for $archive" >&2
  exit 1
}
printf '%s\n' "$entry" | shasum -a 256 -c -
```

Verification must report `OK` for the file you downloaded. Do not install an archive whose digest is missing or mismatched.

On Windows, hash the zip and compare it to the matching line in `SHA256SUMS.txt`:

```powershell
Get-FileHash .\wispkey-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

## Verify Sigstore signatures and provenance

Release checksums are signed keylessly with Sigstore. Build provenance and the CycloneDX SBOM are attested with GitHub Artifact Attestations. Both identify this repository, the git commit, and `.github/workflows/release.yml`.

### GitHub CLI (attestations)

```bash
gh attestation verify wispkey-x86_64-unknown-linux-gnu.tar.gz \
  --repo rankupgames/wispkey
```

Repeat for the archive you installed. A successful check proves the file was built by the WispKey release workflow from the tagged commit.

### Cosign (checksum signature)

```bash
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/rankupgames/wispkey/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

Then re-run the checksum verification above so the signed digest list matches the files on disk.

## SBOM

Each release includes `wispkey.cyclonedx.json`, a CycloneDX 1.5 bill of materials generated from the tagged crate graph. GitHub stores a Sigstore SBOM attestation for the same artifacts:

```bash
gh attestation verify wispkey.cyclonedx.json --repo rankupgames/wispkey
```

## Fail-closed publication

For a non-dry-run tag operation, the Cargo registry token preflight and every pre-publication gate must succeed before external publication starts:

- `cargo fmt --check`, clippy, tests, `cargo audit`, and `cargo publish --dry-run`
- native builds for Linux x64/ARM64, macOS x64/ARM64, and Windows x64
- archive smoke tests of the downloaded binary on each of those platforms
- Homebrew formula install and formula test of the macOS archive
- SHA-256 checksums, CycloneDX SBOM, Sigstore checksum signatures, and build provenance

If a pre-publication gate or the token preflight fails, GitHub Releases, the Homebrew formula, and crates.io are not updated.

External publication is sequential, not atomic: the workflow publishes the GitHub Release, tests the published Homebrew formula, publishes to crates.io, and then runs the crates.io install acceptance check. A later failure can leave an earlier destination updated. For recovery, inspect the existing release and crates.io version before retrying, then use GitHub Actions' `Re-run failed jobs` after fixing the failed step. Do not try to republish a version that is already present on crates.io; crate versions are immutable.
