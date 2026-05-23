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
- **Wisp token proxy** -- HTTP forward proxy + blind HTTPS CONNECT tunneling + HTTPS reverse proxy mode (`X-Target-Url` header) on localhost:7700
- **CLI** -- Full credential lifecycle: `init`, `unlock`, `add`, `list`, `get`, `remove`, `rotate`, `import`, `status`, `log`
- **MCP server** -- Native integration with Cursor, Claude Code, Windsurf via stdio JSON-RPC, including first-class env-sideloaded credentials for locked-vault use
- **.env importer** -- One-command migration with auto-detection of OpenAI, GitHub, Slack, AWS, and bearer token patterns

### Organization
- **Projects** -- Top-level credential isolation by team or engagement (`project create`, `use`, `current`, `list`, `delete`)
- **Partitions** -- Logical credential grouping within projects, with encrypted `.wkbundle` export/import (`partition create`, `list`, `delete`, `assign`, `export`, `import`)

### Security
- **Policy engine** -- TOML-defined rules with per-credential, per-host, per-path, per-method restrictions, deny rules, time windows, and sliding-window rate limiting
- **Audit log** -- Every credential use and denial logged with timestamp, target host/path, method, and status; queryable by credential and date range
- **Host restrictions** -- Glob-pattern allowlists per credential (e.g. `api.openai.com/*`)
- **Cross-OS local file protection** -- Vault directories and sensitive local files are owner-only on Linux/macOS and restricted with Windows ACLs on Windows

### Cloud (groundwork -- auth and encrypted sync/share APIs)
- **Browser-based Clerk login** -- `wispkey cloud login` opens browser, localhost callback captures session token
- **Tier enforcement** -- Personal (free, local-only), Cloud ($1.99/mo), Enterprise (contact)
- **Environment sideload** -- MCP/proxy processes can receive `WISPKEY_SIDELOAD_{SLUG}` env vars and expose them as deterministic `wk_env_{slug}` tokens. Agents still receive only opaque tokens, and no vault master password is required for this path.

## Credential Types

WispKey stores arbitrary encrypted secret values, not only API keys from `.env` files. Use `api_key` as the generic opaque secret type for passwords, database URLs, SSH/private-key files, webhook secrets, OAuth tokens, service-account JSON, and anything else that should stay out of the agent process. The type mainly controls how the proxy injects or substitutes the value at request time.

| Type | CLI Flag | Injection |
|------|----------|-----------|
| Bearer Token | `--type bearer_token` | `Authorization: Bearer <value>` |
| API Key | `--type api_key` | Header or body replacement |
| Basic Auth | `--type basic_auth` | `Authorization: Basic <base64>` |
| Custom Header | `--type custom_header --header-name X-Api-Key` | Named header |
| Query Param | `--type query_param --param-name key` | URL query parameter |

Examples:

```bash
wispkey add "db-password" --type api_key --value "correct-horse-battery-staple" --tags "database"
wispkey add "db-url" --type api_key --value "postgres://user:pass@localhost/app" --tags "database"
wispkey add "ssh-private-key" --type api_key --value-file ~/.ssh/id_ed25519 --partition "ssh-keys"
wispkey add "service-account-json" --type api_key --value-file ./service-account.json --tags "gcp"
wispkey add "basic-auth-api" --type basic_auth --value "user:password" --hosts "api.example.com"
```

## MCP Integration

Configure in Cursor, Claude Code, or any MCP-compatible tool. Keep the command as `wispkey` so the client uses the normal installed binary from `PATH`; do not hardcode a user-specific absolute path. Vault-backed credentials use the current WispKey session; run `wispkey unlock` before starting the client, or set `WISPKEY_PASSWORD` only for trusted automation.

```json
{
  "mcpServers": {
    "wispkey": {
      "command": "wispkey",
      "args": ["mcp", "serve"]
    }
  }
}
```

For env-sideloaded MCP credentials, pass `WISPKEY_SIDELOAD_<SLUG>` to the WispKey MCP process instead of passing the vault master password. WispKey lists the env key and returns a `wk_env_<slug>` token; it never returns the env value. In Codex, use `env_vars` so Codex forwards the variable from its own environment instead of storing the secret in config:

```toml
[mcp_servers.wispkey]
command = "wispkey"
args = ["mcp", "serve"]
env_vars = ["WISPKEY_SIDELOAD_OPENAI"]
```

Start the WispKey proxy with the same `WISPKEY_SIDELOAD_<SLUG>` env var if you want the proxy to substitute the `wk_env_<slug>` token in outbound requests.

For JSON-style MCP configs that do not support `env_vars`, set the sideload variable in the client process environment or in the MCP server's `env` block:

```json
{
  "mcpServers": {
    "wispkey": {
      "command": "wispkey",
      "args": ["mcp", "serve"],
      "env": { "WISPKEY_SIDELOAD_OPENAI": "..." }
    }
  }
}
```

Treat MCP `env` blocks as plaintext client config. Prefer process environment forwarding or an OS credential manager when available.

Available MCP tools:
- `wispkey_list` -- List credentials (filter by tag, project)
- `wispkey_get_token` -- Get wisp token for a credential
- `wispkey_proxy_status` -- Check vault/session/proxy state
- `wispkey_project_list` -- List all projects with partition counts

## HTTPS Proxy

WispKey supports HTTPS in two ways:

**CONNECT tunneling** (standard forward proxy) -- the agent sets `HTTP_PROXY=http://localhost:7700` and the proxy tunnels the TLS connection. CONNECT is a blind tunnel: the proxy cannot inspect or rewrite headers, bodies, or query strings inside the TLS stream. Use CONNECT only when the request does not need wisp token substitution.

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
Each project gets its own `personal` partition, so partition names are project-scoped.

```bash
wispkey project create "client-alpha" --description "Client Alpha credentials"
wispkey project use "client-alpha"
wispkey project current
wispkey project list
wispkey project export "client-alpha" --output client-alpha.wkbundle
wispkey project import client-alpha.wkbundle
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

Exports are encrypted with a separate bundle passphrase, not the vault master password. The bundle file contains real secrets after decryption, so share the file and passphrase through different channels. New exports require a 12+ character bundle passphrase.

For non-interactive bundle operations, use `WISPKEY_BUNDLE_PASSPHRASE` or a protected passphrase file:

```bash
export WISPKEY_BUNDLE_PASSPHRASE='a-long-export-passphrase'
wispkey project export "client-alpha" --output client-alpha.wkbundle

wispkey project import client-alpha.wkbundle \
  --bundle-passphrase-file ~/.wispkey/client-alpha.bundle-passphrase
```

## Single Credential Bundles

Export and import one encrypted credential for narrow sharing:

```bash
wispkey credential export "openai-key" --output openai-key.wkcred
wispkey credential import openai-key.wkcred --project client-alpha --partition personal
```

## Non-Interactive Mode (CI / Agents)

Set `WISPKEY_PASSWORD` to skip interactive prompts:

```bash
export WISPKEY_PASSWORD='your-master-password'
wispkey init
wispkey unlock
wispkey add "key" --type api_key --value "secret"
```

`WISPKEY_PASSWORD` only unlocks or initializes the vault. It is intentionally not used for encrypted bundle export/import; use `WISPKEY_BUNDLE_PASSPHRASE` or `--bundle-passphrase-file` for those commands.

`wispkey mcp serve` does not require `WISPKEY_PASSWORD` when you only need env-sideloaded credentials. Set `WISPKEY_SIDELOAD_<SLUG>` in the MCP server environment and ask for credential name `<slug>` (case and separators are normalized).

Older `WISPKEY_FALLBACK_<SLUG>` names are not supported. Rename those variables to `WISPKEY_SIDELOAD_<SLUG>` before upgrading.

## Project Structure

```
src/
  core/       # Vault engine (encrypt/decrypt, CRUD, wisp tokens, projects, partitions)
  proxy/      # HTTP/HTTPS proxy (tokio + hyper, credential injection, policy eval, env sideload)
  mcp/        # MCP server (stdio JSON-RPC transport)
  cli/        # CLI interface (clap, 37 subcommands)
  audit/      # Audit logging (SQLite, credential + time filtering)
  migrate/    # .env file importer (auto-detection heuristics)
  partition/  # Encrypted bundle export/import (.wkbundle)
  secure_files.rs # Cross-platform owner-only local file protection
  sharing/    # Project and single-credential encrypted share bundles
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
cargo test            # Run all 86 tests (72 unit + 14 integration)
cargo clippy --all-targets --all-features -- -D warnings -W clippy::suspicious -W clippy::style -W clippy::perf -W clippy::complexity
cargo fmt --check     # Format check
cargo audit           # Dependency advisory check (install with: cargo install cargo-audit --version 0.22.1 --locked)
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
