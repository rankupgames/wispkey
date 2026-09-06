---
name: wispkey-env-migration
description: Migrate .env files to WispKey wisp tokens. Use when the user wants to import secrets from .env, convert environment files, replace hardcoded secrets, or migrate to WispKey.
---

# WispKey .env Migration

## Discover And Attach

Find existing environment files without reading their contents:
```bash
wispkey env list .
wispkey env list . --format json
```

Attach only the secret-bearing keys. The project and environment partition are created when missing:
```bash
wispkey env attach .env.production \
  --project my-app \
  --key OPENAI_API_KEY \
  --key GITHUB_TOKEN
wispkey project use my-app
```

This will:
1. Import only the explicitly selected `--key` values
2. Store them under project `my-app` and environment partition `production`
3. Preserve unselected settings, comments, quoting, and the existing file path
4. Atomically replace selected plaintext values with wisp tokens
5. Restrict the attached file to owner-only permissions

## Output

Original `.env.production`:
```
OPENAI_API_KEY=sk-abc123...
GITHUB_TOKEN=ghp_xyz789...
```

Attached `.env.production`:
```
OPENAI_API_KEY=wk_production_openai_api_key_f3k2m1x8
GITHUB_TOKEN=wk_production_github_token_p9q7r5s3
```

## Scope Mapping

Organization/account scope remains external to the local vault:

```text
Organization > WispKey Project > Environment Partition > Credential
```

`.env` maps to environment `default`; `.env.production` maps to `production`. Use `--environment <name>` to override this. Credential names are environment-prefixed, such as `production-openai-api-key`.

## Using The Attached File

1. Start the proxy: `wispkey serve`
2. Load the same `.env` path as before
3. Route inspectable HTTP through `HTTP_PROXY=http://localhost:7700`
4. Send HTTPS requests containing tokens through reverse proxy mode with `X-Target-Url`; CONNECT cannot substitute inside TLS

Attached tokens are not automatically converted when a process reads its environment. Attach only values used through an HTTP substitution path. Use `wispkey run`, `exec`, or `inject` for database URLs, ports, paths, and other non-HTTP values.

The proxy and MCP use the active project by default. Run `wispkey project use <project>` after attaching, or use `wispkey serve --all-projects` only when resolving tokens across projects is intended. Attached tokens are specific to that local vault and should not be treated as portable team configuration.

Attachment cannot infer target hosts. Configure restrictive policies, or pre-provision the matching environment-prefixed credentials with `--hosts`, before exposing attached tokens to an untrusted agent.

## Handling Duplicates

Matching stored values and existing tokens are safe to re-attach. A different stored value, unknown token, or cross-environment credential fails without changing the file.

## Whole-File Import

`wispkey import .env` remains available when a separate `.env.wispkey` output file is desired. Prefer `env attach` when the existing file should stay in place and only selected secrets should become tokens.

## Post-Migration Checklist

1. Verify the environment: `wispkey list --project my-app --partition production`
2. Confirm ordinary local settings are unchanged
3. Keep `.env` ignored when it contains machine-vault-specific tokens; do not present those tokens as portable team configuration
4. Start the proxy before local testing
