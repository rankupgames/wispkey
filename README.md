# WispKey

**Your AI agents work. Your secrets stay home.**

Local-first, open-source credential vault that lets AI agents authenticate and use API keys without ever seeing the plaintext secret. Uses the "wisp token" pattern: agents receive opaque placeholders, a local proxy swaps them for real credentials at the network boundary.

## Quick Start

```bash
# Install (once published)
brew install wispkey
# -- or --
cargo install wispkey

# Create your vault
wispkey init

# Import existing .env credentials
wispkey import .env

# Start the proxy
wispkey serve
```

Four commands from zero to protected. The AI process never touches your real secrets.

## How It Works

```
[AI Agent]  -->  "Authorization: Bearer wk_openai_prod_a7x9m2k4"
                        |
              [WispKey Proxy @ localhost:7700]
                        |
              Decrypts real key, swaps it in
                        |
              [OpenAI API]  <--  "Authorization: Bearer sk-real-key..."
```

1. You store credentials in an encrypted local vault (AES-256-GCM, Argon2id key derivation)
2. WispKey generates wisp tokens (`wk_*`) for each credential
3. AI agents use wisp tokens in their requests
4. The proxy intercepts, swaps wisp for real, forwards to the target API
5. The agent never sees, stores, or can exfiltrate the real secret

## MVP Scope (v0.1)

- **Encrypted local vault** -- AES-256-GCM at rest, Argon2id master key, SQLite backend
- **Wisp token proxy** -- HTTP/HTTPS forward proxy on localhost:7700
- **CLI** -- Full credential lifecycle management
- **MCP server mode** -- Native integration with Claude Code, Cursor, Windsurf
- **.env importer** -- One-command migration from existing .env files
- **Audit log** -- Every credential use logged (no sensitive values)

## Project Structure

```
src/
  core/      # Vault engine (encrypt/decrypt, CRUD, wisp tokens)
  proxy/     # HTTP proxy (tokio + hyper, credential injection)
  mcp/       # MCP server mode (stdio transport)
  cli/       # CLI interface (clap)
  audit/     # Audit logging
  migrate/   # .env file importer
```

## Development Setup

### Prerequisites

- **Rust 1.94+** (install via [rustup](https://rustup.rs))
- **SQLite** (bundled via `rusqlite`, no system install needed)

### Build & Run

```bash
# Clone
git clone https://github.com/rankupgames/wispkey.git
cd wispkey

# Build (debug)
cargo build

# Build (release, optimized)
cargo build --release

# Run
cargo run -- init
cargo run -- serve

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

### Cross-Compilation Targets

```bash
# Add targets for release builds
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for a specific target
cargo build --release --target aarch64-apple-darwin
```

## Architecture

| Component | Crate | Purpose |
|-----------|-------|---------|
| Async runtime | `tokio` | Concurrent proxy connections |
| HTTP proxy | `hyper` | High-performance request interception |
| Encryption | `ring` + `argon2` | AES-256-GCM vault, Argon2id key derivation |
| Database | `rusqlite` (bundled) | Zero-config encrypted credential store |
| CLI | `clap` | Rich CLI with shell completions |
| Serialization | `serde` + `serde_json` + `toml` | Config and MCP protocol |
| Logging | `tracing` | Structured logging |

## Spec Docs

Internal planning docs live in `_docs/` (gitignored):
- `_docs/product-spec.md` -- Full product specification
- `_docs/market-research.md` -- Competitive landscape analysis

## License

Apache-2.0
