# WispKey -- Agent Reference

> Local-first credential vault with wisp token proxy.
> Agents get opaque `wk_*` tokens; the proxy swaps them for real secrets at the network boundary.

## Quick Start

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"

wispkey init
wispkey add "openai-key" --type bearer_token --value "sk-..." --hosts "api.openai.com"
wispkey serve
export HTTP_PROXY=http://localhost:7700
```

## Non-Interactive Mode (CI / Agents)

Set `WISPKEY_PASSWORD` to skip interactive prompts:
```bash
export WISPKEY_PASSWORD='your-master-password'
wispkey init
wispkey add "key" --type api_key --value "secret"
```

## CLI Reference

| Command | Purpose |
|---------|---------|
| `wispkey init` | Create vault + master password |
| `wispkey unlock` | Unlock vault (30 min session) |
| `wispkey add <name> [--type TYPE] [--value VAL] [--value-file PATH] [--hosts H] [--tags T] [--partition P]` | Store credential |
| `wispkey list [--partition P]` | List credentials (names only) |
| `wispkey get <name> [--show-token]` | Credential details + wisp token |
| `wispkey remove <name>` | Delete credential |
| `wispkey rotate <name>` | Regenerate wisp token |
| `wispkey serve [--port 7700]` | Start proxy |
| `wispkey import <path> [--prefix P] [--partition P]` | Import .env file |
| `wispkey status` | Vault + session + proxy status |
| `wispkey log [--last N] [--credential C] [--since DATE]` | Audit log |
| `wispkey partition create/list/delete/assign/export/import` | Partition management |
| `wispkey mcp serve` | Start MCP server (stdio) |

## Credential Types

| Type | `--type` value | Use case |
|------|---------------|----------|
| Bearer Token | `bearer_token` | `Authorization: Bearer <value>` |
| API Key | `api_key` | Generic secret value |
| Basic Auth | `basic_auth` | `user:pass` format |
| Custom Header | `custom_header` | Requires `--header-name` |
| Query Param | `query_param` | Requires `--param-name` |

## MCP Tools

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
- **`wispkey_list`** -- List credentials (filter by `tag`)
- **`wispkey_get_token`** -- Get wisp token for a credential by `name`
- **`wispkey_proxy_status`** -- Check vault/session/proxy state

## Key Paths

| Path | Purpose |
|------|---------|
| `~/.wispkey/vault.db` | Encrypted credential database |
| `~/.wispkey/session` | Session key (30 min TTL, mode 0600) |
| `~/.wispkey/proxy.pid` | Proxy PID (written on `serve`) |
| `WISPKEY_VAULT_PATH` | Override vault directory |

## Conventions

- Credential names: lowercase, hyphen-separated (e.g. `cloudflare-api-token`)
- Tags: comma-separated on `--tags` (e.g. `--tags "cloudflare,production"`)
- Hosts: comma-separated globs on `--hosts` (e.g. `--hosts "api.cloudflare.com,*.workers.dev"`)
- Partitions: logical grouping (e.g. `infrastructure`, `cloud-services`, `ci-cd`)
- Values starting with `-`: use `--value='-1abc...'` (equals syntax)
