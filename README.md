# WispKey

**Your agents get tokens. Your secrets stay behind a controlled boundary.**

WispKey is a local-first, open-source credential firewall for AI agents. Agents receive opaque `wk_*` placeholders; WispKey resolves them to real credentials only at an explicit proxy or owner-run injection boundary. Configure credential host restrictions and policies to constrain where an untrusted agent may use a token.

## Quick Start

```bash
# Build from source
git clone https://github.com/rankupgames/wispkey.git
cd wispkey
cargo build --release
export PATH="$PWD/target/release:$PATH"

# Create your vault
wispkey init

# Find and attach selected secrets from an existing .env
wispkey env list .
wispkey env attach .env --project my-app --key OPENAI_API_KEY
wispkey project use my-app

# Start the proxy
wispkey serve
```

The attached `.env` stays in place: selected secret values become `wk_*` tokens while ordinary settings remain unchanged. Tokens belong to the local vault and are not portable team secrets. They are placeholders, not plaintext environment injection. Requests must use a WispKey substitution path; for HTTPS, send them through reverse proxy mode with `X-Target-Url`. Use `wispkey run`, `exec`, or `inject` for non-HTTP consumers. Because attachment cannot infer target hosts, pre-provision matching host-restricted credentials or configure a policy before exposing attached tokens to an untrusted agent.

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
4. The proxy swaps tokens it can inspect in HTTP requests or HTTPS reverse proxy requests, then forwards upstream
5. Normal agent-facing CLI/MCP surfaces expose tokens rather than plaintext; host restrictions and policies constrain where those tokens may be used when configured

## Features

### Core
- **Encrypted local vault** -- AES-256-GCM at rest, Argon2id master key derivation, SQLite backend, configurable session timeout (default 30 min), machine-bound encrypted session file by default, optional OS-backed or file remembered unlock
- **Wisp token proxy** -- HTTP forward proxy + blind HTTPS CONNECT tunneling + HTTPS reverse proxy mode (`X-Target-Url` header) on localhost:7700
- **CLI** -- Credential lifecycle, project and partition management, encrypted bundle import/export, proxy serving, subprocess/template injection, instance administration, and audit export/tail
- **MCP server** -- Native integration with Cursor, Claude Code, Windsurf via stdio JSON-RPC, including first-class env-sideloaded credentials for locked-vault use
- **Environment sideload** -- MCP/proxy processes can receive `WISPKEY_SIDELOAD_<SLUG>` values and expose only deterministic `wk_env_<slug>` tokens
- **Multi-instance access** -- Enroll ephemeral VMs or worker instances with per-request identity, least-privilege credential scope, scoped bootstrap-token self-enrollment, cross-platform TCP, Unix, Linux AF_VSOCK, and Firecracker UDS-backed vsock listeners, plus host-approved access escalation
- **Rotation-ready instance identities** -- Schedule due-aware 48-character CSPRNG secret rotation with a bounded rollout grace window; the previous secret is retired as soon as the new secret first authenticates
- **Native .env attachment** -- Recursively discover `.env*` files, import explicitly selected secrets into project/environment partitions, and atomically replace plaintext values with `wk_*` tokens in the same file
- **.env importer** -- One-command migration with auto-detection of OpenAI, GitHub, Slack, AWS, and bearer token patterns
- **Optional tray GUI** -- Background desktop tray for owner credential entry over authenticated local IPC, including an atomic OVH API template; see [`docs/tray.md`](docs/tray.md)

### Scope
- **Projects** -- Top-level credential isolation by team or engagement (`project create`, `use`, `current`, `list`, `delete`)
- **Partitions** -- Logical credential grouping within projects, with encrypted `.wkbundle` export/import (`partition create`, `list`, `delete`, `assign`, `export`, `import`)
- **Environments** -- `env attach` maps `.env` to a `default` partition and `.env.<name>` to a `<name>` partition; organization/account scope remains external to the local vault

### Security
- **Policy engine** -- TOML-defined rules with per-credential, per-host, per-path, per-method restrictions, deny rules, time windows, and sliding-window rate limiting
- **Audit log** -- Every credential use and denial logged with timestamp, target host/path, method, and status; vault-backed events are queryable by credential and date range, bulk export supports JSONL/JSON for SIEM egress, `audit tail --follow` streams without skipping same-timestamp events, and vault-less env sideload use writes a local fallback JSONL audit file
- **Host restrictions** -- Glob-pattern allowlists per credential (e.g. `api.openai.com` or `*.amazonaws.com`)
- **Cross-OS local file protection** -- Vault directories, attached `.env` files, generated `.env.wispkey` files, and other sensitive outputs are owner-only on Linux/macOS and restricted with Windows ACLs where supported
- **Management API token checks** -- The proxy compares management tokens in constant time
- **Secret injection for subprocesses and templates** -- `wispkey exec`, `wispkey run`, and `wispkey inject` are audited, owner-only plaintext-egress tools that resolve credentials in-process without placing plaintext in argv, parent env, WispKey stdout except explicit `inject --stdout`, or audit logs
- **Security model** -- The current boundary and intentional limits are documented in [`docs/security-model.md`](docs/security-model.md)

### Cloud Groundwork
- **Local session commands** -- `cloud status`, `login`, and `logout` persist local Clerk session metadata
- **Sync status** -- `cloud push`, `pull`, and `sync` are currently stubs and return a clear `coming soon` error; local vault, proxy, bundles, and sharing remain fully usable without Cloud

## Credential Types

WispKey stores arbitrary encrypted secret values, not only API keys from `.env` files. Use `api_key` as the generic opaque secret type for passwords, database URLs, SSH/private-key files, webhook secrets, OAuth tokens, service-account JSON, and anything else that should stay out of the agent process. The type mainly controls how the proxy injects or substitutes the value at request time.

For non-interactive adds, prefer `--value-file <path>` or `--value-file -` for stdin. `--value` still works, but WispKey warns on stderr because command-line arguments can be exposed through shell history and process listings.

| Type | CLI Flag | Injection |
|------|----------|-----------|
| Bearer Token | `--type bearer_token` | `Authorization: Bearer <value>` |
| API Key | `--type api_key` | Header or body replacement |
| Basic Auth | `--type basic_auth` | `Authorization: Basic <base64>` |
| Custom Header | `--type custom_header --header-name X-Api-Key` | Named header |
| Query Param | `--type query_param --param-name key` | URL query parameter |
| Website Login | `wispkey login generate` | Encrypted username+password for a bound HTTPS origin. Not injected by the HTTP proxy; browser fill is a later trusted-handoff slice. |

Website logins are generated by WispKey so the password never appears in argv, stdout, MCP results, or audit logs:

```bash
wispkey project create "career-ops" --description "Career Ops credentials"
wispkey partition create "job-applications" --project career-ops
wispkey login generate employer-name \
  --username user@example.com \
  --url https://careers.example.com \
  --project career-ops \
  --partition job-applications \
  --review-after 180d
```

The same generator works for any website login, not only job portals. Output is metadata only. Lifecycle is `pending` until you `wispkey login activate`, and `wispkey login archive` / `restore` never auto-delete. `wispkey login list --due` lists review-dated logins without deleting them.

Examples:

```bash
printf '%s' "$DB_PASSWORD" | wispkey add "db-password" --type api_key --value-file - --tags "database"
printf '%s' "$DATABASE_URL" | wispkey add "db-url" --type api_key --value-file - --tags "database"
wispkey add "ssh-private-key" --type api_key --value-file ~/.ssh/id_ed25519 --partition "ssh-keys"
wispkey add "service-account-json" --type api_key --value-file ./service-account.json --tags "gcp"
printf '%s' "$BASIC_AUTH_VALUE" | wispkey add "basic-auth-api" --type basic_auth --value-file - --hosts "api.example.com"
```

## Secret Injection (`wispkey exec`, `wispkey run`, `wispkey inject`)

For non-HTTP consumers such as `sudo`, `ssh`, `git`, database CLIs, and local tools, `wispkey exec` resolves a vault credential in-process and injects it only into the child process:

```bash
# Stdin channel, useful for commands such as sudo -S.
wispkey exec --credential laptop-password --stdin -- sudo -S -p "" whoami

# Child-only environment variable.
wispkey exec --credential db-password --env DB_PASSWORD -- psql "$DATABASE_URL"

# Askpass helpers for sudo/ssh/git. Use sudo -A so sudo calls SUDO_ASKPASS.
wispkey exec --credential laptop-password --askpass -- sudo -A whoami
wispkey exec --credential git-token --askpass -- git fetch
```

At least one channel is required: `--stdin`, `--env <VAR>`, or `--askpass`. Channels can be combined. The credential is resolved within the active project, or within `--project <name>` when provided.

`--stdin` writes the secret followed by one newline and closes the child's stdin. Commands that also need interactive stdin should use `--env` or `--askpass` instead.

`exec` is a deliberate, owner-only plaintext-egress path for tools that cannot use the WispKey proxy. It is audited with `CredentialExec` events, but the audit row contains only the credential name, child program name, channel summary, project, and exit status. WispKey does not put the plaintext value in argv, the parent environment, WispKey stdout/stderr, tracing logs, or audit fields. The hidden askpass helper is not a standalone secret oracle: `exec --askpass` creates a per-exec owner-only handoff file and passes its path through `WISPKEY_ASKPASS_HANDOFF`; the helper refuses to run without a valid handoff from that child launch.

For tools that need multiple child-only environment variables, `wispkey run` reads a TOML manifest and resolves every `cred:<name>` reference before spawning the child:

```toml
# wispkey.toml
[env]
OPENAI_API_KEY = "cred:openai-key"
DATABASE_URL = "cred:db-url"
APP_ENV = "development"
```

```bash
wispkey run -- npm test
wispkey run --manifest ./secrets/wispkey.toml --project client-alpha -- sh -c 'psql "$DATABASE_URL"'
```

Manifest values without the `cred:` prefix are passed through as literal child environment values. `run` fails closed when the manifest is missing, invalid, has no `[env]` entries, or any referenced credential cannot be resolved. It writes a `CredentialRun` audit event with the credential names, child program name, project, and exit status.

For config files or templates, `wispkey inject` replaces `{{ cred:<name> }}` references and writes the rendered plaintext to an owner-only output file:

```bash
wispkey inject -i .env.template -o .env.local
wispkey inject -i config.template --stdout
```

`--stdout` is an explicit plaintext disclosure to the caller. The safer default is `-o <outfile>`, which uses WispKey's owner-only file writer. `inject` writes a `CredentialInject` audit event with the credential names, output destination, and project.

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

Start the WispKey proxy with the same `WISPKEY_SIDELOAD_<SLUG>` env var if you want the proxy to substitute the `wk_env_<slug>` token in outbound requests. Env sideloads are limited to the trusted local workflow; identity-authenticated instances cannot use them because sideloads have no persisted credential ID that can be enrolled or approved.

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
- `wispkey_set` -- Create or update a credential (requires `overwrite: true` to replace)
- `wispkey_delete` -- Delete a credential by name
- `wispkey_issue_cert` -- Issue a leaf certificate from a CA key stored in the vault; the CA private key is never returned

## HTTPS Proxy

WispKey supports HTTPS in two ways:

**CONNECT tunneling** (standard forward proxy) -- the client sets `HTTPS_PROXY=http://localhost:7700` and the proxy tunnels the TLS connection. CONNECT is a blind tunnel: the proxy cannot inspect or rewrite headers, bodies, or query strings inside the TLS stream. Use CONNECT only when the request does not need wisp token substitution.

**Reverse proxy mode** -- use `X-Target-Url` for explicit HTTPS targeting:

```bash
curl http://localhost:7700 \
  -H "X-Target-Url: https://api.openai.com/v1/chat/completions" \
  -H "Authorization: Bearer wk_openai_prod_a7x9m2k4" \
  -d '{"model": "gpt-4", "messages": [...]}'
```

Reverse proxy mode substitutes wisp tokens in headers, supported text bodies, and the `X-Target-Url` query string before forwarding upstream.

## Multi-Instance Access

WispKey can serve untrusted ephemeral VMs and worker instances without giving them plaintext secrets. The host enrolls each instance, gives it a one-time id and secret plus `wk_*` tokens, and runs the proxy on one or more listeners:

```bash
wispkey instance enroll worker-acme-001 --tag company:acme --credential openai-key
wispkey serve --listen tcp://127.0.0.1:7700 --listen unix:/run/wispkey/proxy.sock
```

For fleets, the host can mint a scoped bootstrap token and let each VM self-enroll for its own instance id and secret. Successful redemptions are atomic, so TTL and max-use limits are enforced under concurrent joins:

```bash
wispkey instance bootstrap create --tag company:acme --ttl 1h --uses 50
printf '%s' "$BOOTSTRAP_TOKEN" | wispkey instance join --token-file - --name worker-acme-001
```

Remote first-contact self-enrollment can use `POST /api/instances/join`; that endpoint is authenticated by the bootstrap token and does not require a management token or existing instance identity.

Unix domain socket, Linux vsock, Firecracker vsock, and non-loopback TCP listeners require instance identity by default. Loopback TCP keeps the original trusted-local behavior unless `--require-identity` is set. For Windows or another server, keep WispKey on loopback and reach it through an SSH tunnel, or use an identity-required host-only TCP network. Credential selectors and approvals bind to the resolved credential ID rather than its project-local display name. Out-of-scope vault-token use returns `403 out_of_scope`, queues an access request, and can be approved by the host; env-sideload tokens are always out of scope for authenticated instances:

```bash
wispkey instance requests --pending
wispkey instance approve req_...
```

Instance secrets can be rotated safely from cron, systemd timers, CI, or Windows Task Scheduler. The command emits a new one-time secret only when rotation is due:

```bash
wispkey --format json instance rotate-secret worker-acme-001 \
  --if-older-than 30d \
  --grace 15m
```

Deliver the JSON result through a protected deployment channel and do not log its stdout. During the grace window both secrets work; the first successful request with the new secret retires the previous secret immediately.

See [`docs/multi-instance-deployment.md`](docs/multi-instance-deployment.md) for the deployment model, listener options, and a Firecracker microVM example.

## How WispKey Compares

WispKey is not a traditional secrets manager. Traditional vaults are built to deliver plaintext secrets to trusted applications; WispKey is built for agents that should never hold plaintext secrets at all.

- **Versus agent credential proxies** -- WispKey is a local Rust binary with a policy engine, audit trail, explicit HTTP token substitution, audited non-HTTP injection, first-class MCP tooling, and env sideload support for locked-vault workflows.
- **Versus enterprise access platforms** -- WispKey does not require a cloud account, sales motion, or hosted control plane for local use. Secrets can stay on the user's machine.
- **Versus plaintext `.env` files** -- WispKey can attach selected HTTP-facing secrets in place as tokens while preserving ordinary settings. Non-HTTP secrets stay behind explicit `run`, `exec`, or `inject` boundaries.

Security claims are intentionally scoped: CONNECT is a blind tunnel, loopback TCP keeps the trusted-local default, authenticated instance listeners are scoped and fail closed, text-body substitution is limited to text-like content types, and the machine-bound session store does not defend against a same-user process that can read all local WispKey files or inspect memory. See [`docs/security-model.md`](docs/security-model.md) for the public security model.

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
time_window = "09:00-17:00" # local machine time
```

Manage policies via CLI:

```bash
wispkey policy init     # Create starter policies.toml
wispkey policy list     # Show loaded policies
wispkey policy check    # Validate policy file
```

Agent-scoped policies fail closed when the requester agent identity is unavailable. The proxy does not currently have a trusted agent identity source, so a policy with an `agent = "..."` scope still applies to proxy requests.

## Project Scoping

Credentials are isolated by project. Each project contains partitions, which contain credentials.
Each project gets its own `personal` partition, so partition names are project-scoped.
Credential names are unique within a project, not across the whole vault. The same credential name can exist in different projects. CLI name lookups such as `get`, `remove`, and `rotate` resolve against the active project; API lookups can use an explicit `?project=` scope. Existing vaults migrate to schema v11 automatically.

For `.env` attachment, the WispKey project represents the source project and the filename maps to an environment partition: `.env` becomes `default`, while `.env.production` becomes `production`. Organization/account scope remains external to the local vault.

`env attach` cannot infer the intended upstream host. Attached credentials have no host allowlist unless a matching environment-prefixed credential was pre-provisioned with `--hosts`; configure host restrictions or policies before treating a token as safe for an untrusted agent.

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

The proxy management API also honors project scope for `GET /api/credentials`, `GET /api/credentials/{name}`, `DELETE /api/credentials/{name}`, `GET /api/partitions`, and `DELETE /api/partitions/{name}` by passing `?project=<name>`.

## Command Reference

| Command | Purpose |
|---------|---------|
| `wispkey init` | Create vault and master password |
| `wispkey unlock [--timeout N] [--remember] [--protector-timeout N] [--password-file PATH\|-]` | Unlock vault for the current session; `--remember` stores a password-free re-unlock protector |
| `wispkey lock [--forget]` | Revoke the current session; `--forget` also deletes the remembered protector |
| `wispkey tray [--ipc-only]` | Start authenticated owner IPC; optionally spawn the tray GUI |
| `wispkey add <name> [--type TYPE] [--value-file PATH|-] [--hosts H] [--tags T] [--partition P] [--project P]` | Store a credential |
| `wispkey list [--partition P] [--project P] [--all-projects]` | List credentials |
| `wispkey get <name> [--show-token]` | Show credential metadata and wisp token |
| `wispkey remove <name>` | Delete a credential |
| `wispkey rotate <name>` | Regenerate a wisp token |
| `wispkey exec --credential <name> [--project P] [--stdin] [--env VAR]... [--askpass] -- <command> [args...]` | Inject a credential into a child process through audited stdin, child-only env, or askpass channels |
| `wispkey run [--manifest PATH] [--project P] -- <command> [args...]` | Run a child process with manifest-defined child-only environment variables |
| `wispkey inject -i <infile|-> [-o <outfile>] [--project P] [--stdout]` | Render `{{ cred:<name> }}` template references to an owner-only file or explicit stdout |
| `wispkey serve [--port 7700] [--random-port] [--listen SPEC]... [--require-identity|--no-require-identity] [--all-projects] [--daemon]` | Start the proxy; `SPEC` supports `tcp://host:port`, `unix:/path.sock`, feature-gated Linux `vsock://cid:port`, and `firecracker-vsock:/path.sock:port` |
| `wispkey proxy status/stop/cleanup` | Inspect, stop, or clean up local proxy lifecycle state |
| `wispkey env list [directory]` | Recursively list attachable `.env*` files without reading their contents; use `--format json` for automation |
| `wispkey env attach <path> --project P --key NAME... [--environment E]` | Import selected secrets into a project/environment and replace their values with WispKey tokens in the same file |
| `wispkey import <path> [--prefix P] [--partition P] [--project P]` | Legacy whole-file import that writes a sibling `.env.wispkey` file |
| `wispkey login generate <name> --username U --url HTTPS [--project P] [--partition P] [--review-after 180d]` | Generate and store a unique website login without printing the password |
| `wispkey login list [--due] [--project P] [--all-projects]` | List website-login metadata |
| `wispkey login archive/restore/activate <name>` | Lifecycle changes; archive never deletes |
| `wispkey status` | Show vault, session, and proxy status |
| `wispkey log [--last N] [--credential C] [--since DATE]` | Query audit events |
| `wispkey audit export [--since TS] [--until TS] [--credential C] [--encoding jsonl|json] [-o FILE]` | Export matching audit events for SIEM ingestion |
| `wispkey audit tail [--follow] [--credential C]` | Stream newest audit events as JSONL; `--follow` uses a forward `(timestamp,id)` cursor |
| `wispkey policy list/init/check` | List, initialize, or validate local access policies |
| `wispkey partition create/list/delete/assign/export/import` | Manage partitions |
| `wispkey project create/list/delete/use/current/export/import` | Manage projects and encrypted project bundles |
| `wispkey credential export/import` | Export or import one encrypted credential bundle |
| `wispkey instance enroll <name> [--description D] [--partition P]... [--project P]... [--credential C]... [--tag T]...` | Enroll a host-managed instance identity |
| `wispkey instance list/show/scope/revoke/requests/approve/deny` | List, inspect, scope, revoke, and approve or deny instance access requests |
| `wispkey instance rotate-secret <name> [--if-older-than 30d] [--grace 10m]` | Schedule-safe instance-secret rotation with bounded overlap |
| `wispkey instance bootstrap create/list/revoke` | Manage scoped, atomic bootstrap tokens for fleet self-enrollment |
| `wispkey instance join [<bootstrap-token>] [--token-file <path|->] --name <instance-name>` | Redeem a bootstrap token; prefer `--token-file -` to avoid argv exposure |
| `wispkey cloud status/login/logout` | Manage local Cloud session groundwork |
| `wispkey cloud push/pull/sync` | Reserved sync commands; currently return `coming soon` |
| `wispkey mcp serve` | Start the MCP server over stdio |

## Tray GUI

The optional `wispkey-tray` binary is a desktop extension of the CLI. Start owner IPC with `wispkey tray` (or `wispkey tray --ipc-only` for tests), then add single credentials or the OVH API template from a native dialog. Secrets stay off argv and never pass through an unauthenticated localhost form. Closing a dialog leaves the tray running. See [`docs/tray.md`](docs/tray.md).

## Partition Bundles

Export and import encrypted credential bundles for sharing or backup:

```bash
wispkey partition create "staging" --description "Staging API keys"
wispkey partition assign "my-credential" --to "staging"
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

Do not pass the master password as a CLI argument. Prefer a remembered protector or an owner-only password file:

```bash
wispkey unlock --remember --password-file ~/.wispkey/master.pass
wispkey lock                 # revoke the 30-minute session
wispkey unlock               # remint a session from the protector, no password prompt
wispkey lock --forget        # drop the protector too
```

`WISPKEY_PASSWORD` still skips interactive prompts for trusted local automation:

```bash
export WISPKEY_PASSWORD='your-master-password'
wispkey init
wispkey unlock
printf '%s' "$SECRET_VALUE" | wispkey add "key" --type api_key --value-file -
```

For non-interactive secret input, prefer `wispkey add "key" --type api_key --value-file ./secret.txt` or pipe the value to `--value-file -`. Passing secrets with `--value` emits a warning because the value can be captured by shell history or process listings.

`WISPKEY_PASSWORD` only unlocks or initializes the vault. It is intentionally not used for encrypted bundle export/import; use `WISPKEY_BUNDLE_PASSPHRASE` or `--bundle-passphrase-file` for those commands.

`wispkey mcp serve` does not require `WISPKEY_PASSWORD` when you only need env-sideloaded credentials. Set `WISPKEY_SIDELOAD_<SLUG>` in the MCP server environment and ask for credential name `<slug>` (case and separators are normalized).

Older `WISPKEY_FALLBACK_<SLUG>` names are not supported. Rename those variables to `WISPKEY_SIDELOAD_<SLUG>` before upgrading.

## Project Structure

```
src/
  core/       # Vault engine (encrypt/decrypt, CRUD, wisp tokens, projects, partitions)
  proxy/      # HTTP/HTTPS proxy (tokio + hyper, credential injection, policy eval, env sideload)
  mcp/        # MCP server (stdio JSON-RPC transport)
  cli/        # CLI interface (clap subcommands)
  audit/      # Audit logging (SQLite, credential + time filtering)
  migrate/    # .env discovery, attachment, and legacy import workflows
  partition/  # Encrypted bundle export/import (.wkbundle)
  secure_files.rs # Cross-platform owner-only local file protection
  sharing/    # Project and single-credential encrypted share bundles
  cloud/      # Cloud session groundwork and sync command stubs
  policy/     # Policy engine (TOML rules, rate limiting, time windows)
tests/             # Command-focused integration tests
plugin/           # Cursor plugin (rules, skills, hooks, agents)
```

## Development

### Prerequisites

- Current stable **Rust** via [rustup](https://rustup.rs)
- SQLite is bundled via `rusqlite` -- no system install needed

### Build and Test

```bash
git clone https://github.com/rankupgames/wispkey.git
cd wispkey

cargo build           # Debug build
cargo build --release # Optimized release build
cargo test --all-features # Run the full test suite
cargo clippy --all-targets --all-features -- -D warnings -W clippy::suspicious -W clippy::style -W clippy::perf -W clippy::complexity
cargo fmt --all -- --check # Format check
cargo audit           # Dependency advisory check (install with: cargo install cargo-audit --locked)
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
| CLI | `clap` | Subcommand parsing |
| Serialization | `serde` + `serde_json` + `toml` | Config, policy, and MCP protocol |
| HTTP client | `reqwest` | Cloud API client groundwork (rustls-tls) |
| Logging | `tracing` | Structured logging with env filter |
| Patterns | `glob-match` + `regex` | Host restriction globs, wisp token scanning |
| Browser | `open` | Clerk login flow (opens default browser) |

## Related Repositories

- **[WispKey Cloud](https://github.com/rankupgames/wispkey-cloud)** (private) -- Optional companion-service repository; CLI data sync is not implemented in this repository
- **[WispKey Desktop](https://github.com/rankupgames/wispkey-desktop)** (private) -- Tauri + SvelteKit desktop companion app

## WispKey Cloud Roadmap

The open-source CLI works fully offline with no account. Cloud login/session groundwork exists, but CLI sync operations are not implemented yet. The optional Cloud companion is planned for encrypted sync and team workflows:

| Planned tier | Price | Intended scope |
|------|-------|--------------|
| **Personal** | Free | Everything in this repo -- local vault, proxy, MCP, plugin |
| **Cloud** | $1.99/mo ($1.49/mo annual) | Planned encrypted sync, up to 10 cloud partitions, 100 MB storage |
| **Enterprise** | Contact us | Planned unlimited partitions, org management, SSO, and dedicated support |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
