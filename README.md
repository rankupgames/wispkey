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

## Features

- **Encrypted local vault** -- AES-256-GCM at rest, Argon2id master key, SQLite backend
- **Wisp token proxy** -- HTTP forward proxy on localhost:7700
- **CLI** -- Full credential lifecycle (add, list, get, remove, rotate, import)
- **MCP server** -- Native integration with Cursor, Claude Code, Windsurf (stdio transport)
- **.env importer** -- One-command migration from existing .env files
- **Partitions** -- Logical credential grouping with encrypted export/import
- **Projects** -- Credential isolation by team or project (scoped partitions, scoped proxy)
- **Audit log** -- Every credential use logged (no sensitive values)
- **Cursor plugin** -- Rules, skills, hooks, and MCP wiring for IDE agents

## Credential Types

| Type | CLI Flag | Injection |
|------|----------|-----------|
| Bearer Token | `--type bearer_token` | `Authorization: Bearer <value>` |
| API Key | `--type api_key` | Header or body replacement |
| Basic Auth | `--type basic_auth` | `Authorization: Basic <base64>` |
| Custom Header | `--type custom_header --header-name X-Api-Key` | Named header |
| Query Param | `--type query_param --param-name key` | URL query parameter |

## MCP Integration

Configure in Cursor, Claude Code, or any MCP-compatible tool:

```json
{
  "mcpServers": {
    "wispkey": {
      "command": "wispkey",
      "args": ["mcp", "serve"],
      "env": { "WISPKEY_PASSWORD": "your-master-password" }
    }
  }
}
```

Available MCP tools:
- `wispkey_list` -- List credentials (filter by tag, project)
- `wispkey_get_token` -- Get wisp token for a credential
- `wispkey_proxy_status` -- Check vault/session/proxy state
- `wispkey_project_list` -- List all projects with partition counts

## Project Scoping

Credentials are isolated by project. Each project contains partitions, which contain credentials.

```bash
wispkey project create "client-alpha" --description "Client Alpha credentials"
wispkey project use "client-alpha"
wispkey project current
wispkey project list
wispkey list --all-projects
wispkey serve --all-projects
```

Override per-terminal with `export WISPKEY_PROJECT=client-alpha`.

## Non-Interactive Mode (CI / Agents)

Set `WISPKEY_PASSWORD` to skip interactive prompts:

```bash
export WISPKEY_PASSWORD='your-master-password'
wispkey init
wispkey unlock
wispkey add "key" --type api_key --value "secret"
```

## Project Structure

```
src/
  core/       # Vault engine (encrypt/decrypt, CRUD, wisp tokens)
  proxy/      # HTTP proxy (tokio + hyper, credential injection)
  mcp/        # MCP server (stdio transport)
  cli/        # CLI interface (clap)
  audit/      # Audit logging
  migrate/    # .env file importer
  partition/  # Encrypted bundle export/import
  cloud/      # Cloud sync client (WispKey Cloud)
plugin/       # Cursor plugin (rules, skills, hooks, agents)
```

## Development

### Prerequisites

- **Rust 1.94+** via [rustup](https://rustup.rs)
- SQLite is bundled via `rusqlite` -- no system install needed

### Build and Test

```bash
git clone https://github.com/rankupgames/wispkey.git
cd wispkey

cargo build           # Debug build
cargo build --release # Optimized release build
cargo test            # Run all 48 tests
cargo clippy -- -D warnings  # Lint
cargo fmt --check     # Format check
```

### Cross-Compilation

```bash
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cargo build --release --target aarch64-apple-darwin
```

## Architecture

| Component | Crate | Purpose |
|-----------|-------|---------|
| Async runtime | `tokio` | Concurrent proxy connections |
| HTTP proxy | `hyper` | High-performance request interception |
| Encryption | `ring` + `argon2` | AES-256-GCM vault, Argon2id key derivation |
| Database | `rusqlite` (bundled) | Zero-config encrypted credential store |
| CLI | `clap` | Subcommand parsing with shell completions |
| Serialization | `serde` + `serde_json` + `toml` | Config and MCP protocol |
| Logging | `tracing` | Structured logging with env filter |

## WispKey Cloud

The open-source CLI works fully offline -- no account needed. [WispKey Cloud](https://api.wispkey.com) is an optional companion for encrypted sync and team workflows:

| Tier | Price | What you get |
|------|-------|--------------|
| **Personal** | Free | Everything in this repo -- local vault, proxy, MCP, plugin |
| **Cloud** | $1.99/mo | Encrypted sync, up to 10 cloud partitions, 100 MB storage |
| **Enterprise** | Contact us | Unlimited partitions, org management, dedicated support |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
