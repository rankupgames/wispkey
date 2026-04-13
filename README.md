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
4. The proxy intercepts headers, body, and query parameters -- swaps wisp for real, forwards to the target API
5. The agent never sees, stores, or can exfiltrate the real secret

## Features

### Core
- **Encrypted local vault** -- AES-256-GCM at rest, Argon2id master key derivation, SQLite backend, configurable session timeout (default 30 min)
- **Wisp token proxy** -- HTTP forward proxy + HTTPS CONNECT tunneling + reverse proxy mode (`X-Target-Url` header) on localhost:7700
- **CLI** -- Full credential lifecycle: `init`, `unlock`, `add`, `list`, `get`, `remove`, `rotate`, `import`, `status`, `log`
- **MCP server** -- Native integration with Cursor, Claude Code, Windsurf via stdio JSON-RPC
- **.env importer** -- One-command migration with auto-detection of OpenAI, GitHub, Slack, AWS, and bearer token patterns

### Organization
- **Projects** -- Top-level credential isolation by team or engagement (`project create`, `use`, `current`, `list`, `delete`)
- **Partitions** -- Logical credential grouping within projects, with encrypted `.wkbundle` export/import (`partition create`, `list`, `delete`, `assign`, `export`, `import`)

### Security
- **Policy engine** -- TOML-defined rules with per-credential, per-host, per-path, per-method restrictions, deny rules, time windows, and sliding-window rate limiting
- **Audit log** -- Every credential use and denial logged with timestamp, target host/path, method, and status; queryable by credential and date range
- **Host restrictions** -- Glob-pattern allowlists per credential (e.g. `api.openai.com/*`)

### Cloud (groundwork -- sync stubs, auth complete)
- **Browser-based Clerk login** -- `wispkey cloud login` opens browser, localhost callback captures session token
- **Tier enforcement** -- Personal (free, local-only), Cloud ($1.99/mo), Enterprise (contact)
- **Environment fallback** -- If a wisp token lookup fails, the proxy checks `WISPKEY_FALLBACK_{SLUG}` env vars and records an auto-fix note to `.wispkey/auto-fix-notes.json`

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

## HTTPS Proxy

WispKey supports HTTPS in two ways:

**CONNECT tunneling** (standard forward proxy) -- the agent sets `HTTP_PROXY=http://localhost:7700` and the proxy tunnels the TLS connection. Wisp token substitution happens in headers before the tunnel is established.

**Reverse proxy mode** -- use `X-Target-Url` for explicit HTTPS targeting:

```bash
curl -x http://localhost:7700 \
  -H "X-Target-Url: https://api.openai.com/v1/chat/completions" \
  -H "Authorization: Bearer wk_openai_prod_a7x9m2k4" \
  -d '{"model": "gpt-4", "messages": [...]}'
```

## Policy Engine

Define credential access rules in `~/.wispkey/policies.toml`:

```toml
[[policy]]
name = "restrict-production"
credential = "aws-prod"
allowed_methods = ["GET"]
denied_paths = ["/admin/**", "/delete/**"]
allowed_hosts = ["api.aws.com"]
rate_limit = "10/minute"
time_window = "09:00-17:00 America/New_York"
```

Manage policies via CLI:

```bash
wispkey policy init     # Create starter policies.toml
wispkey policy list     # Show loaded policies
wispkey policy check    # Validate policy file
```

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

## Partition Bundles

Export and import encrypted credential bundles for sharing or backup:

```bash
wispkey partition create "staging" --description "Staging API keys"
wispkey partition assign "my-credential" --partition "staging"
wispkey partition export "staging" --output staging.wkbundle
wispkey partition import staging.wkbundle
```

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
  core/       # Vault engine (encrypt/decrypt, CRUD, wisp tokens, projects, partitions)
  proxy/      # HTTP/HTTPS proxy (tokio + hyper, credential injection, policy eval, env fallback)
  mcp/        # MCP server (stdio JSON-RPC transport)
  cli/        # CLI interface (clap, 37 subcommands)
  audit/      # Audit logging (SQLite, credential + time filtering)
  migrate/    # .env file importer (auto-detection heuristics)
  partition/  # Encrypted bundle export/import (.wkbundle)
  cloud/      # Cloud sync client (Clerk browser login, tier enforcement)
  policy/     # Policy engine (TOML rules, rate limiting, time windows)
tests/
  integration.rs  # CLI integration tests
plugin/           # Cursor plugin (rules, skills, hooks, agents)
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
cargo test            # Run all 75 tests (70 unit + 5 integration)
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
| HTTP proxy | `hyper` + `hyper-rustls` | HTTP/HTTPS request interception and CONNECT tunneling |
| Encryption | `ring` + `argon2` | AES-256-GCM vault, Argon2id key derivation |
| Database | `rusqlite` (bundled) | Zero-config credential store + audit log |
| CLI | `clap` | Subcommand parsing with shell completions |
| Serialization | `serde` + `serde_json` + `toml` | Config, policy, and MCP protocol |
| HTTP client | `reqwest` | Cloud API calls (rustls-tls) |
| Logging | `tracing` | Structured logging with env filter |
| Patterns | `glob-match` + `regex` | Host restriction globs, wisp token scanning |
| Browser | `open` | Clerk login flow (opens default browser) |

## Related Repositories

- **[WispKey Cloud](https://github.com/rankupgames/wispkey-cloud)** (private) -- Cloudflare Worker API for encrypted cloud sync, billing, and team features
- **[WispKey Desktop](https://github.com/rankupgames/wispkey-desktop)** -- Tauri + SvelteKit desktop companion app

## WispKey Cloud

The open-source CLI works fully offline -- no account needed. [WispKey Cloud](https://api.wispkey.com) is an optional companion for encrypted sync and team workflows:

| Tier | Price | What you get |
|------|-------|--------------|
| **Personal** | Free | Everything in this repo -- local vault, proxy, MCP, plugin |
| **Cloud** | $1.99/mo ($1.49/mo annual) | Encrypted sync, up to 10 cloud partitions, 100 MB storage |
| **Enterprise** | Contact us | Unlimited partitions, org management, SSO, dedicated support |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
