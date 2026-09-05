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

- Current stable **Rust** via [rustup](https://rustup.rs)
- That's it -- SQLite is bundled via `rusqlite`

## Development Workflow

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Run the full check suite:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Default `cargo test` and `cargo clippy` build the CLI crate only (`default-members = ["."]`). The optional `wispkey-tray` GUI is a workspace member but is not required for CI. To build it locally on Debian/Ubuntu:

```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev
cargo build -p wispkey-tray
```

See [`docs/tray.md`](docs/tray.md) for owner IPC and tray usage.

4. Open a PR against `main`

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

Use the repository's GitHub issue forms. Keep one concern per issue and search
existing issues and pull requests before submitting a new report.

Feature requests use this structure:

- **Problem:** the concrete limitation, risk, or unsupported workflow.
- **Goal:** the observable outcome, separate from implementation details.
- **Scope:** the behavior and surfaces included in the request.
- **Proposed interface:** a CLI, MCP, API, UI, or data-contract sketch when useful.
- **Acceptance criteria:** testable checklist items, including fail-closed and
  secret-redaction behavior where relevant.
- **Evidence:** current code, documentation, or sanitized behavior that proves
  the gap exists.
- **Non-goals and overlap:** exclusions and related issues or pull requests.

Bug reports must include expected behavior, minimal reproduction steps, WispKey
version, OS and architecture, Rust version when building from source, the
affected interface, sanitized evidence, and acceptance criteria for the fix.

Never include credentials, tokens, private keys, passwords, vault contents, or
unredacted logs in an issue.

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Email security@rankupgames.com instead. We'll respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
