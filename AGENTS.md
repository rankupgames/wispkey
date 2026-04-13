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
| `wispkey serve [--port 7700]` | Start proxy |
| `wispkey import <path> [--prefix P] [--partition P]` | Import .env file |
| `wispkey status` | Vault + session + proxy status |
| `wispkey log [--last N] [--credential C] [--since DATE]` | Audit log |
| `wispkey partition create/list/delete/assign/export/import` | Partition management |
| `wispkey project create/list/delete/use/current` | Project management |
| `wispkey mcp serve` | Start MCP server (stdio) |

## Credential Types

| Type | `--type` value | Use case |
|------|---------------|----------|
| Bearer Token | `bearer_token` | `Authorization: Bearer <value>` |
| API Key | `api_key` | Generic secret value |
| Basic Auth | `basic_auth` | `user:pass` format |
| Custom Header | `custom_header` | Requires `--header-name` |
| Query Param | `query_param` | Requires `--param-name` |

## MCP Tools (for IDE agents)

Configure in Cursor/Claude Code:
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

Available tools:
- **`wispkey_list`** -- List credentials (filter by `tag`, `project`; defaults to active project, `"*"` for all)
- **`wispkey_get_token`** -- Get wisp token for a credential by `name`
- **`wispkey_proxy_status`** -- Check vault/session/proxy state
- **`wispkey_project_list`** -- List all projects with partition counts and active indicator

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
| `~/.wispkey/session` | Session key (30 min TTL, mode 0600) |
| `~/.wispkey/proxy.pid` | Proxy PID (written on `serve`) |
| `~/.wispkey/active_project` | Persistent active project (set by `project use`) |
| `WISPKEY_VAULT_PATH` | Override vault directory |
| `WISPKEY_PROJECT` | Override active project per-terminal |

## Conventions

- Credential names: lowercase, hyphen-separated (e.g. `cloudflare-api-token`)
- Tags: comma-separated on `--tags` (e.g. `--tags "cloudflare,production"`)
- Hosts: comma-separated globs on `--hosts` (e.g. `--hosts "api.cloudflare.com,*.workers.dev"`)
- Partitions: logical grouping (e.g. `infrastructure`, `cloud-services`, `ci-cd`)
- Projects: team/project isolation (e.g. `client-alpha`, `internal-tools`)
- Values starting with `-`: use `--value='-1abc...'` (equals syntax)
