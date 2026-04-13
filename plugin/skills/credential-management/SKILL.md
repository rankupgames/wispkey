---
name: wispkey-credential-management
description: Manage credentials in the WispKey vault -- add, list, rotate, remove secrets and wisp tokens. Use when the user asks to store a secret, add an API key, manage credentials, rotate tokens, or work with the WispKey vault.
---

# WispKey Credential Management

## Workflow

### Adding a Credential
```bash
wispkey add "<name>" --type <type> --value "<secret>" [--hosts "<hosts>"] [--tags "<tags>"] [--partition "<partition>"]
```

Types: `bearer_token` (default), `api_key`, `basic_auth`, `custom_header`, `query_param`

Optional **`--partition`** places the credential inside a named partition. Create the partition first with `wispkey partition create` if it does not exist (see the partition-management skill).

Example:
```bash
wispkey add "openai-prod" --type bearer_token --value "sk-abc123..." --hosts "api.openai.com" --tags "ai,production"
```

Example with partition:
```bash
wispkey add "openai-prod" --type bearer_token --value "sk-abc123..." --hosts "api.openai.com" --partition "ml-services"
```

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
wispkey add "stripe-key" --type bearer_token --value "sk_live_..." --hosts "api.stripe.com"
```
Glob patterns supported: `--hosts "*.amazonaws.com"`

## Tags

Organize credentials:
```bash
wispkey add "db-prod" --type basic_auth --value "user:pass" --tags "database,production"
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
