# WispKey -- Agent Reference

> Local-first credential vault with wisp token proxy.
> Agents get opaque `wk_*` tokens; the proxy swaps them for real secrets at the network boundary.

## Quick Start (New User)

```bash
# 1. Build (or use pre-built binary)
cargo build --release
export PATH="$PWD/target/release:$PATH"

# 2. Initialize vault (prompts for master password)
wispkey init

# 3. Add credentials
wispkey add "openai-key" --type bearer_token --value "sk-..." --hosts "api.openai.com"
wispkey add "db-creds" --type basic_auth --value "user:pass" --tags "database"
wispkey add "ssh-key" --type api_key --value-file ~/.ssh/my_key --partition "ssh-keys"

# 4. Start proxy
wispkey serve

# 5. Use in your agent environment
export HTTP_PROXY=http://localhost:7700
```

## Non-Interactive Mode (CI / Agents)

Set `WISPKEY_PASSWORD` to skip interactive prompts:
```bash
export WISPKEY_PASSWORD='your-master-password'
wispkey init        # no prompt
wispkey unlock      # no prompt
wispkey add "key" --type api_key --value "secret"  # no prompt
```

## Project Scoping

Credentials are isolated by project. Each project contains partitions, which contain credentials.
By default all commands scope to the active project.

```bash
# Create a project
wispkey project create "client-alpha" --description "Client Alpha credentials"

# Set active project (persists across sessions)
wispkey project use "client-alpha"

# Override per-terminal
export WISPKEY_PROJECT=client-alpha

# View active project
wispkey project current

# List all projects
wispkey project list

# List credentials across all projects
wispkey list --all-projects

# Start proxy scoped to active project (default)
wispkey serve

# Start proxy allowing all projects
wispkey serve --all-projects
```

## CLI Reference

| Command | Purpose |
|---------|---------|
| `wispkey init` | Create vault + master password |
| `wispkey unlock` | Unlock vault (30 min session) |
| `wispkey add <name> [--type TYPE] [--value VAL] [--value-file PATH] [--hosts H] [--tags T] [--partition P]` | Store credential |
| `wispkey list [--partition P] [--project P] [--all-projects]` | List credentials (names only) |
| `wispkey get <name> [--show-token]` | Credential details + wisp token |
| `wispkey remove <name>` | Delete credential |
| `wispkey rotate <name>` | Regenerate wisp token |
| `wispkey serve [--port 7700] [--all-projects] [--daemon]` | Start proxy (HTTP + HTTPS reverse) |
| `wispkey import <path> [--prefix P] [--partition P] [--project P]` | Import .env file |
| `wispkey status` | Vault + session + proxy status |
| `wispkey log [--last N] [--credential C] [--since DATE]` | Audit log |
| `wispkey partition create/list/delete/assign/export/import` | Partition management |
| `wispkey project create/list/delete/use/current/export/import` | Project management and encrypted project bundles |
| `wispkey credential export/import` | Encrypted single-credential sharing bundles |
| `wispkey mcp serve` | Start MCP server (stdio) |

## Credential Types

| Type | `--type` value | Use case |
|------|---------------|----------|
| Bearer Token | `bearer_token` | `Authorization: Bearer <value>` |
| API Key | `api_key` | Generic secret value |
| Basic Auth | `basic_auth` | `user:pass` format |
| Custom Header | `custom_header` | Requires `--header-name` |
| Query Param | `query_param` | Requires `--param-name` |

WispKey stores arbitrary encrypted secret values, not only API keys. Use `api_key` as the generic opaque type for passwords, database URLs, SSH/private-key files via `--value-file`, webhook secrets, OAuth tokens, service-account JSON, and other secret material. The credential type controls proxy injection behavior, not what can be stored.

The proxy scans and replaces wisp tokens in three locations: **headers**, **request body** (text/json/form only), and **URL query parameters**.

## Encrypted Export Bundles

Partition, project, and single-credential exports are passphrase-protected encrypted bundles:
```bash
wispkey project export "client-alpha" --output client-alpha.wkbundle
wispkey partition export "infrastructure" --output infrastructure.wkbundle
wispkey credential export "openai-key" --output openai-key.wkcred
```

Bundle passphrases are separate from the vault master password. `WISPKEY_PASSWORD` unlocks the vault only; it is not used for bundle export/import. For non-interactive bundle operations, set `WISPKEY_BUNDLE_PASSPHRASE` or use `--bundle-passphrase-file`:
```bash
export WISPKEY_BUNDLE_PASSPHRASE='a-long-export-passphrase'
wispkey project import client-alpha.wkbundle

wispkey credential import openai-key.wkcred \
  --bundle-passphrase-file ~/.wispkey/openai-key.bundle-passphrase
```

New exports require a 12+ character bundle passphrase. Share the encrypted bundle and passphrase through different channels.

## MCP Tools (for IDE agents)

Configure in Cursor/Claude Code. Keep `command` as `wispkey` so clients use the normal installed binary from `PATH`; do not hardcode a user-specific absolute path. Prefer an unlocked WispKey session for vault-backed credentials; use `WISPKEY_PASSWORD` only for trusted automation.
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

For locked-vault MCP use, pass env sideloads instead of the master password. In Codex, use `env_vars` to forward a variable from the Codex process environment:
```toml
[mcp_servers.wispkey]
command = "wispkey"
args = ["mcp", "serve"]
env_vars = ["WISPKEY_SIDELOAD_OPENAI"]
```

`WISPKEY_SIDELOAD_<SLUG>` values are exposed to agents only as deterministic `wk_env_<slug>` tokens. The raw env value must never be printed or logged.

For JSON MCP configs that do not support `env_vars`, set the sideload variable in the client process environment or in the server `env` block. Treat `env` blocks as plaintext client config and prefer process environment forwarding or an OS credential manager when available.

Available tools:
- **`wispkey_list`** -- List credentials (filter by `tag`, `project`; defaults to active project, `"*"` for all)
- **`wispkey_get_token`** -- Get wisp token for a credential by `name`
- **`wispkey_proxy_status`** -- Check vault/session/proxy state
- **`wispkey_project_list`** -- List all projects with partition counts and active indicator

## HTTPS Proxy (Reverse Proxy Mode)

CONNECT tunneling is blind and cannot swap `wk_*` tokens inside TLS. For HTTPS token substitution, send the request to WispKey's reverse proxy mode with the `X-Target-Url` header:
```bash
curl http://localhost:7700 \
  -H "X-Target-Url: https://api.openai.com/v1/chat/completions" \
  -H "Authorization: Bearer wk_openai_prod_a7x9m2k4" \
  -d '{"model": "gpt-4", "messages": [...]}'
```

The proxy terminates TLS upstream, swaps wisp tokens, and forwards. The agent never sees the real credential.

## Proxy Management API

When the proxy is running (`wispkey serve`):

| Endpoint | Returns |
|----------|---------|
| `GET /api/status` | Vault info, credential count, session state |
| `GET /api/credentials` | All credentials with tokens (no plaintext values) |
| `GET /api/partitions` | All partitions with credential counts |
| `GET /api/projects` | All projects with partition counts and active flag |
| `GET /api/projects/{name}` | Single project details |

## Key Paths

| Path | Purpose |
|------|---------|
| `~/.wispkey/vault.db` | Encrypted credential database |
| `~/.wispkey/session` | Session key (30 min TTL; owner-only permissions on Unix, restricted ACL on Windows) |
| `~/.wispkey/proxy.pid` | Proxy PID (written on `serve`) |
| `~/.wispkey/proxy.json` | Proxy discovery file with management token (owner-only permissions/ACL) |
| `~/.wispkey/active_project` | Persistent active project (set by `project use`) |
| `WISPKEY_VAULT_PATH` | Override vault directory |
| `WISPKEY_PROJECT` | Override active project per-terminal |
| `WISPKEY_BUNDLE_PASSPHRASE` | Non-interactive passphrase for encrypted bundle export/import |
| `WISPKEY_SIDELOAD_<SLUG>` | Env-sideload credential value for MCP/proxy use; never print the value |

## Conventions

- Credential names: lowercase, hyphen-separated (e.g. `cloudflare-api-token`)
- Tags: comma-separated on `--tags` (e.g. `--tags "cloudflare,production"`)
- Hosts: comma-separated globs on `--hosts` (e.g. `--hosts "api.cloudflare.com,*.workers.dev"`)
- Partitions: logical grouping (e.g. `infrastructure`, `cloud-services`, `ci-cd`)
- Projects: team/project isolation (e.g. `client-alpha`, `internal-tools`)
- Values starting with `-`: use `--value='-1abc...'` (equals syntax)
