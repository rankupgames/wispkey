---
name: setup-wispkey
description: Initialize WispKey, attach selected .env secrets, and start the proxy. Use when the user says "setup wispkey", "init wispkey", or "secure my secrets".
---

# Setup WispKey

Quick setup for a new project.

## Steps

1. **Initialize the vault** (if not already done):
   ```bash
   wispkey init
   ```

2. **Discover existing `.env` files** without reading their contents:
   ```bash
   wispkey env list .
   ```

3. **Attach only secret keys that will use WispKey's HTTP substitution path**:
   ```bash
   wispkey env attach .env --project my-app --key OPENAI_API_KEY
   wispkey project use my-app
   ```

   This keeps the same file, preserves unselected settings, and replaces selected values with `wk_*` tokens. Do not attach ports, paths, database URLs, or other non-HTTP values; use `wispkey run`, `exec`, or `inject` for those. Before exposing tokens to an untrusted agent, pre-provision matching host-restricted credentials or configure a restrictive policy.

4. **Start the proxy**:
   ```bash
   wispkey serve
   ```

5. **Verify**:
   ```bash
   wispkey status
   wispkey list --project my-app --partition default
   ```

6. **Configure MCP**. Keep `command` as `wispkey` so the client uses the normal installed binary from `PATH`:
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

   For locked-vault MCP use, sideload credentials instead of passing the vault master password:
   ```toml
   [mcp_servers.wispkey]
   command = "wispkey"
   args = ["mcp", "serve"]
   env_vars = ["WISPKEY_SIDELOAD_OPENAI"]
   ```

   The MCP server returns `wk_env_openai` and the env key name, never the raw env value. For sideload-only setup, launch the proxy with the same variable: `WISPKEY_SIDELOAD_OPENAI="$OPENAI_API_KEY" wispkey serve`.

After setup, inspectable HTTP requests can use `HTTP_PROXY=http://localhost:7700`. `HTTPS_PROXY` is a blind CONNECT tunnel and cannot substitute tokens; HTTPS requests containing `wk_*` values must use reverse proxy mode with `X-Target-Url`.
