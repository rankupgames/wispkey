---
name: wispkey-credential-management
description: Manage credentials in the WispKey vault -- add, list, rotate, remove secrets and wisp tokens. Use when the user asks to store a secret, add an API key, manage credentials, rotate tokens, or work with the WispKey vault.
---

# WispKey Credential Management

## Workflow

### Adding a Credential
```bash
wispkey add "<name>" --type <type> --value-file <path|-> [--hosts "<hosts>"] [--tags "<tags>"] [--partition "<partition>"] [--project "<project>"]
```

Types: `bearer_token` (default), `api_key`, `basic_auth`, `custom_header`, `query_param`

Website logins are not added with `wispkey add`. Generate them so the password never enters argv or the agent context:

```bash
wispkey login generate "acme-careers" \
  --username user@example.com \
  --url https://careers.example.com \
  --project career-ops \
  --partition job-applications \
  --review-after 180d
```

`api_key` is the generic opaque-secret type. Use it for passwords, database URLs, SSH/private-key files, webhook secrets, OAuth tokens, service-account JSON, and other encrypted values that do not need a more specific proxy injection behavior.

Prefer `--value-file <path>` for non-interactive secret input, or `--value-file -` to read from stdin. `--value` still works, but WispKey warns on stderr because the value can be exposed through shell history and process listings. Omitting both flags uses the hidden prompt.

Optional **`--partition`** places the credential inside a named partition. Create the partition first with `wispkey partition create` if it does not exist (see the partition-management skill).

Example:
```bash
printf '%s' "$OPENAI_API_KEY" | wispkey add "openai-prod" --type bearer_token --value-file - --hosts "api.openai.com" --tags "ai,production"
```

Example with partition:
```bash
wispkey add "openai-prod" --type bearer_token --value-file ./openai.key --hosts "api.openai.com" --partition "ml-services"
```

Examples for non-API-key secrets:
```bash
wispkey add "db-password" --type api_key --value-file ./db-password.txt --tags "database"
wispkey add "ssh-private-key" --type api_key --value-file ~/.ssh/id_ed25519 --partition "ssh-keys"
wispkey add "service-account-json" --type api_key --value-file ./service-account.json --tags "gcp"
```

Credential names are unique per project, not vault-wide. The same name can exist in different projects; `add`, `list`, and import workflows can use `--project`, while `get`, `remove`, and `rotate` resolve names in the active project.

### Listing Credentials
```bash
wispkey list
```
Shows names, types, and tags. Never shows values.

List only credentials in one partition:
```bash
wispkey list --partition "<partition-name>"
```

### Getting a Wisp Token
```bash
wispkey get "<name>" --show-token
```
Returns the `wk_*` token for use in API calls.

### Rotating a Token
```bash
wispkey rotate "<name>"
```
Generates a new wisp token. Old token stops working immediately.

### Removing a Credential
```bash
wispkey remove "<name>"
```

## Host Restrictions

Bind credentials to specific hosts for defense-in-depth:
```bash
printf '%s' "$STRIPE_API_KEY" | wispkey add "stripe-key" --type bearer_token --value-file - --hosts "api.stripe.com"
```
Glob patterns supported: `--hosts "*.amazonaws.com"`

## Tags

Organize credentials:
```bash
printf '%s' "$DB_BASIC_AUTH" | wispkey add "db-prod" --type basic_auth --value-file - --tags "database,production"
```

## Session Management

The vault auto-locks after 30 minutes. Unlock with:
```bash
wispkey unlock
```

For non-interactive/CI usage:
```bash
export WISPKEY_PASSWORD=<master-password>
```

For MCP/proxy workflows where the vault should stay locked, use env sideload credentials instead of the master password:
```bash
export WISPKEY_SIDELOAD_OPENAI="$OPENAI_API_KEY"
wispkey mcp serve
```

The MCP tool returns a deterministic `wk_env_openai` token and the env key name only. Start `wispkey serve` with the same `WISPKEY_SIDELOAD_OPENAI` variable when outbound requests need token substitution. Never print or log the raw sideload value.
