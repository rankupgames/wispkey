# WispKey -- Agent Reference

> Local-first credential firewall for AI agents with wisp token proxy.
> Agents get opaque `wk_*` tokens; the proxy swaps them for real secrets at the network boundary.

## Quick Start (New User)

```bash
# 1. Build (or use pre-built binary)
cargo build --release
export PATH="$PWD/target/release:$PATH"

# 2. Initialize vault (prompts for master password)
wispkey init

# 3. Add credentials
printf '%s' "$OPENAI_API_KEY" | wispkey add "openai-key" --type bearer_token --value-file - --hosts "api.openai.com"
printf '%s' "$BASIC_AUTH_VALUE" | wispkey add "db-creds" --type basic_auth --value-file - --tags "database"
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
printf '%s' "$SECRET_VALUE" | wispkey add "key" --type api_key --value-file -  # no prompt
```

`wispkey add --value` still works, but warns on stderr because command-line arguments can be exposed through shell history and process listings. Prefer `--value-file <path>` or `--value-file -` for non-interactive secret input.

## Project Scoping

Credentials are isolated by project. Each project contains partitions, which contain credentials.
By default all commands scope to the active project.
Credential names are unique within a project, not vault-wide. The same name can exist in different projects. CLI name lookups such as `get`, `remove`, and `rotate` resolve in the active project; API lookups can use an explicit `?project=` scope. Existing vaults migrate to schema v10 automatically.

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

## Multi-Instance Access

The default `wispkey serve` listener remains loopback TCP with no instance identity requirement for the original trusted-local workflow. For untrusted ephemeral VMs or worker instances, enroll an instance and use identity-required listeners such as Unix domain sockets, non-loopback TCP, feature-gated Linux AF_VSOCK, or Firecracker's UDS-backed vsock bridge:

```bash
wispkey instance enroll "worker-acme-001" --credential openai-key --tag company:acme
wispkey serve --listen unix:/run/wispkey/proxy.sock
wispkey serve --listen firecracker-vsock:/run/wispkey/worker.vsock:7700
```

Instances authenticate every proxied request with `x-wispkey-instance-id` and `x-wispkey-instance-secret`. Credential selectors and approvals bind to the resolved credential ID, so same-named credentials in other projects remain out of scope. Out-of-scope vault-token use returns `403 out_of_scope`, queues or reuses an access request, and requires host approval with `wispkey instance approve <request-id>` before retry. Env-sideload credentials have no enrollable credential ID and are denied for instance-authenticated requests.

Rotate instance secrets from a protected scheduler path with `wispkey --format json instance rotate-secret <name> --if-older-than 30d --grace 15m`. Treat stdout as a one-time secret channel. The old secret remains valid only for the grace window and is retired early after the new secret first authenticates.

For fleets, mint scoped bootstrap tokens and redeem them with `--token-file` so the token does not appear in argv:
```bash
wispkey instance bootstrap create --tag company:acme --ttl 1h --uses 50
printf '%s' "$BOOTSTRAP_TOKEN" | wispkey instance join --token-file - --name worker-acme-001
```

Bootstrap redemption is atomic and race-safe; TTL and max-use limits are enforced under concurrent joins. The proxy management API also exposes `POST /api/instances/join` for first-contact self-enrollment authenticated only by the bootstrap token.

## Secret Injection

`wispkey exec`, `wispkey run`, and `wispkey inject` are audited, owner-only plaintext-egress tools for non-HTTP consumers that cannot use the token proxy.

```bash
wispkey exec --credential laptop-password --stdin -- sudo -S -p "" whoami
wispkey exec --credential laptop-password --askpass -- sudo -A whoami
wispkey run --manifest ./secrets/wispkey.toml -- npm test
wispkey inject -i .env.template -o .env.local
```

`exec --askpass` creates a per-exec owner-only handoff capability file and passes it with `WISPKEY_ASKPASS_HANDOFF`; the hidden `wispkey askpass` helper refuses to run without a valid handoff from that child launch. The old `WISPKEY_ASKPASS_CRED` path is not supported.

## CLI Reference

| Command | Purpose |
|---------|---------|
| `wispkey init` | Create vault + master password |
| `wispkey unlock` | Unlock vault (30 min session) |
| `wispkey add <name> [--type TYPE] [--value VAL] [--value-file PATH|-] [--hosts H] [--tags T] [--partition P] [--project P]` | Store credential |
| `wispkey list [--partition P] [--project P] [--all-projects]` | List credentials (names only) |
| `wispkey get <name> [--show-token]` | Credential details + wisp token |
| `wispkey remove <name>` | Delete credential |
| `wispkey rotate <name>` | Regenerate wisp token |
| `wispkey exec --credential <name> [--project P] [--stdin] [--env VAR]... [--askpass] -- <command> [args...]` | Audited child-process secret injection |
| `wispkey run [--manifest PATH] [--project P] -- <command> [args...]` | Manifest-defined child-only environment injection |
| `wispkey inject -i <infile|-> [-o <outfile>] [--project P] [--stdout]` | Render `{{ cred:<name> }}` references to owner-only file output or explicit stdout |
| `wispkey serve [--port 7700] [--random-port] [--listen SPEC]... [--require-identity|--no-require-identity] [--all-projects] [--daemon]` | Start proxy; `SPEC` supports TCP, Unix sockets, feature-gated Linux AF_VSOCK, and Firecracker UDS-backed vsock |
| `wispkey import <path> [--prefix P] [--partition P] [--project P]` | Import .env file |
| `wispkey status` | Vault + session + proxy status |
| `wispkey log [--last N] [--credential C] [--since DATE]` | Audit log |
| `wispkey audit export [--since TS] [--until TS] [--credential C] [--encoding jsonl|json] [-o FILE]` | Export matching audit events |
| `wispkey audit tail [--follow] [--credential C]` | Stream newest audit events with a forward cursor when following |
| `wispkey partition create/list/delete/assign/export/import` | Partition management |
| `wispkey project create/list/delete/use/current/export/import` | Project management and encrypted project bundles |
| `wispkey credential export/import` | Encrypted single-credential sharing bundles |
| `wispkey instance enroll/list/show/scope/bootstrap/join/revoke/requests/approve/deny` | Manage instance identities, bootstrap self-enrollment, scopes, and access requests |
| `wispkey instance rotate-secret <name> [--if-older-than AGE] [--grace AGE]` | Due-aware instance-secret rotation for protected automation |
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

The proxy scans and replaces wisp tokens in three locations: **headers**, **request body** (text/json/form only), and **URL query parameters**. In reverse-proxy mode, this includes wisp tokens in the `X-Target-Url` query string.

Agent-scoped policies fail closed when the requester's agent identity is unavailable. The proxy currently has no trusted agent identity source, so a policy with an `agent = "..."` scope applies to proxy requests even when no agent name is known.

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

Do not add legacy aliases for replaced config surfaces. If a name changes, document the migration to the current name and remove the old path. `WISPKEY_FALLBACK_<SLUG>` is not supported; use `WISPKEY_SIDELOAD_<SLUG>`.

Available tools:
- **`wispkey_list`** -- List credentials (filter by `tag`, `project`; defaults to active project, `"*"` for all)
- **`wispkey_get_token`** -- Get wisp token for a credential by `name`
- **`wispkey_proxy_status`** -- Check vault/session/proxy state
- **`wispkey_project_list`** -- List all projects with partition counts and active indicator
- **`wispkey_set`** -- Create or update a credential (`name`, `value` required; `type`, `description`, `hosts`, `tags`, `project`, `header_name`, `param_name` optional). Refuses to overwrite unless `overwrite: true`. On update, the wisp token is preserved.
- **`wispkey_delete`** -- Delete a credential by `name` (optional `project` scope)

## HTTPS Proxy (Reverse Proxy Mode)

CONNECT tunneling is blind and cannot swap `wk_*` tokens inside TLS. For HTTPS token substitution, send the request to WispKey's reverse proxy mode with the `X-Target-Url` header:
```bash
curl http://localhost:7700 \
  -H "X-Target-Url: https://api.openai.com/v1/chat/completions" \
  -H "Authorization: Bearer wk_openai_prod_a7x9m2k4" \
  -d '{"model": "gpt-4", "messages": [...]}'
```

The proxy terminates TLS upstream, swaps wisp tokens, and forwards. The agent never sees the real credential.

Management API tokens are compared in constant time.

## Proxy Management API

When the proxy is running (`wispkey serve`):

| Endpoint | Returns |
|----------|---------|
| `GET /api/status` | Vault info, credential count, session state |
| `GET /api/credentials` | All credentials with tokens (no plaintext values); honors `?project=` |
| `GET /api/credentials/{name}` | Single credential by name; honors `?project=` |
| `DELETE /api/credentials/{name}` | Delete credential by name; honors `?project=` |
| `GET /api/partitions` | All partitions with credential counts |
| `DELETE /api/partitions/{name}` | Delete partition by name; honors `?project=` |
| `GET /api/projects` | All projects with partition counts and active flag |
| `GET /api/projects/{name}` | Single project details |
| `POST /api/instances/join` | Redeem a bootstrap token for first-contact instance self-enrollment |

## Key Paths

| Path | Purpose |
|------|---------|
| `~/.wispkey/vault.db` | Encrypted credential database (owner-only permissions on Unix) |
| `~/.wispkey/session` | Session key (30 min TTL; owner-only permissions on Unix, restricted ACL on Windows) |
| `~/.wispkey/proxy.pid` | Proxy PID (written on `serve`) |
| `~/.wispkey/proxy.json` | Proxy discovery file with management token (owner-only permissions/ACL) |
| `~/.wispkey/active_project` | Persistent active project (set by `project use`) |
| `.env.wispkey` | Generated import output with wisp tokens (owner-only permissions on Unix) |
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
- Values starting with `-`: use `--value='-1abc...'` (equals syntax), though `--value-file` is preferred for secret material

## Cursor Cloud specific instructions

Single Rust crate (no services/DB to boot; SQLite is bundled via `rusqlite`). Standard dev commands live in `CONTRIBUTING.md` (`cargo build`, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`) and the CI matrix in `.github/workflows/ci.yml`.

- Toolchain: the base image's default Rust is too old to compile this crate (`edition = "2024"` needs Rust ≥ 1.85; the project targets 1.94+). The startup update script installs and defaults the `stable` toolchain (currently 1.98) with `clippy`/`rustfmt`, so just use `cargo`/`clippy`/`fmt` normally. If a session ever lands on old Rust, run `rustup default stable`.
- `cargo test` compiles and boots real loopback TCP proxies; the full suite takes ~2-3 min. This is expected, not a hang.
- Running the CLI/proxy non-interactively: set `WISPKEY_PASSWORD` to skip master-password prompts, and set `WISPKEY_VAULT_PATH` to a scratch dir (e.g. `/tmp/wk-demo`) so you never touch a real `~/.wispkey` vault.
- `wispkey serve` is a long-running foreground process — run it in a tmux session (or `serve --daemon`). Forward-proxy (`HTTP_PROXY`) token swapping only works for plain HTTP; HTTPS requires reverse-proxy mode via the `X-Target-Url` header (see "HTTPS Proxy" above).
