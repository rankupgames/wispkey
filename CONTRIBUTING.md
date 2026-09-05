# Contributing to WispKey

Thanks for your interest in contributing to WispKey. This document covers the basics.

## Getting Started

```bash
git clone https://github.com/rankupgames/wispkey.git
cd wispkey
cargo build
cargo test
```

### Prerequisites

- **Rust 1.94+** via [rustup](https://rustup.rs)
- That's it -- SQLite is bundled via `rusqlite`

## Development Workflow

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Run the full check suite:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Default `cargo test` and `cargo clippy` build the CLI crate only (`default-members = ["."]`). The optional `wispkey-tray` GUI is a workspace member but is not required for CI. To build it locally on Debian/Ubuntu:

```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev
cargo build -p wispkey-tray
```

See [`docs/tray.md`](docs/tray.md) for owner IPC and tray usage.

4. Open a PR against `main`

## Cutting a Release

Releases are tag-driven. `.github/workflows/release.yml` fails closed before publication: GitHub Release assets and `cargo publish` do not run unless tests, clippy, `cargo audit`, `cargo publish --dry-run`, native packaging, downloaded-binary smoke tests, Homebrew formula install/test, checksums, Sigstore signatures, provenance, and the Cargo registry token preflight all succeed.

1. Set `version` in the root `Cargo.toml` (and keep `crates/wispkey-tray` in lockstep if it changed).
2. Update [`CHANGES.md`](CHANGES.md) and [`docs/install.md`](docs/install.md) if the install path changed.
3. Push an annotated tag that matches the crate version, for example `v0.4.0`.
4. Configure the `CARGO_REGISTRY_TOKEN` repository secret before the first crates.io publish. The non-dry-run tag path checks it before any external publication.
5. After the workflow finishes, verify a downloaded archive with the instructions in [`docs/install.md`](docs/install.md).

External publication is sequential rather than atomic. If a post-publication job fails, inspect the existing GitHub Release and crates.io version before using `Re-run failed jobs`; do not republish a version already present on crates.io.

Third-party GitHub Actions in CI and release workflows are pinned to commit SHAs. When bumping an Action, update the pin and the version comment on the same line.

## What We're Looking For

- Bug fixes with a test that reproduces the issue
- New credential types or injection strategies
- MCP tool improvements
- Documentation improvements
- Performance improvements (with benchmarks)

## Code Style

- Run `cargo fmt` before committing
- All clippy warnings must be resolved
- Tests required for new functionality
- Keep functions focused -- single responsibility

## Reporting Issues

Open a GitHub issue with:
- What you expected
- What happened instead
- Steps to reproduce
- OS and Rust version (`rustc --version`)

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Email security@rankupgames.com instead. We'll respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
