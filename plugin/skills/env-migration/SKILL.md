---
name: wispkey-env-migration
description: Migrate .env files to WispKey wisp tokens. Use when the user wants to import secrets from .env, convert environment files, replace hardcoded secrets, or migrate to WispKey.
---

# WispKey .env Migration

## Quick Migration

Import an entire `.env` file in one command:
```bash
wispkey import .env
```

This will:
1. Parse every `KEY=VALUE` pair
2. Auto-detect credential types (OpenAI, GitHub, AWS, Slack, Stripe, etc.)
3. Encrypt and store each credential in the vault
4. Generate `.env.wispkey` with wisp tokens replacing real values

## Output

Original `.env`:
```
OPENAI_API_KEY=sk-abc123...
GITHUB_TOKEN=ghp_xyz789...
```

Generated `.env.wispkey`:
```
OPENAI_API_KEY=wk_openai_api_key_f3k2m1x8
GITHUB_TOKEN=wk_github_token_p9q7r5s3
```

## Using the Migrated File

1. Replace `.env` with `.env.wispkey` in your project
2. Start the proxy: `wispkey serve`
3. Set `HTTP_PROXY=http://localhost:7700` in your runtime environment
4. Requests containing wisp tokens are automatically resolved

## Prefix Option

Namespace imported credentials:
```bash
wispkey import .env --prefix "myapp-"
```
Creates credentials like `myapp-openai-api-key` instead of `openai-api-key`.

## Handling Duplicates

Already-imported credentials are skipped with a notice. Safe to re-run.

## Post-Migration Checklist

1. Verify all credentials imported: `wispkey list`
2. Add `.env` to `.gitignore` (if not already)
3. Commit `.env.wispkey` (safe -- contains only wisp tokens)
4. Update project README with proxy setup instructions
5. Delete the original `.env` once confirmed
