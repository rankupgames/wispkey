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

Open a GitHub issue with:
- What you expected
- What happened instead
- Steps to reproduce
- OS and Rust version (`rustc --version`)

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Email security@rankupgames.com instead. We'll respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
