# Install and Verify WispKey

WispKey ships signed, checksummed binaries for Linux, macOS, and Windows. Prefer a GitHub Release, Homebrew, or `cargo install` over an unsigned copy.

## Install

### Homebrew (macOS and Linux)

```bash
brew install --formula https://github.com/rankupgames/wispkey/releases/latest/download/wispkey.rb
```

This formula installs the platform-matching signed archive from GitHub Releases and checks its SHA-256 digest before extracting.

### Cargo (all supported targets)

```bash
cargo install wispkey --locked
```

crates.io publication runs only after release tests, clippy, `cargo audit`, packaging, Sigstore signing, provenance, and a binary smoke test succeed.

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

# macOS
shasum -a 256 -c SHA256SUMS.txt
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

A version tag does not publish unless every gate succeeds:

- `cargo fmt --check`, clippy, tests, `cargo audit`, and `cargo publish --dry-run`
- native builds for Linux x64/ARM64, macOS x64/ARM64, and Windows x64
- archive smoke tests of the downloaded binary on each of those platforms
- Homebrew formula install of the macOS archive
- SHA-256 checksums, CycloneDX SBOM, Sigstore checksum signatures, and build provenance

If testing, audit, packaging, signing, or provenance generation fails, GitHub Releases and crates.io are not updated.
