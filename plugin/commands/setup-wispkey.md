---
name: setup-wispkey
description: Initialize WispKey vault, import existing .env secrets, and start the proxy. Use when the user says "setup wispkey", "init wispkey", or "secure my secrets".
---

# Setup WispKey

Quick setup for a new project.

## Steps

1. **Initialize the vault** (if not already done):
   ```bash
   wispkey init
   ```

2. **Import existing .env file** (if present):
   ```bash
   wispkey import .env
   ```

3. **Start the proxy**:
   ```bash
   wispkey serve
   ```

4. **Add `.env` to `.gitignore`** and commit `.env.wispkey`:
   ```bash
   echo '.env' >> .gitignore
   ```

5. **Verify**:
   ```bash
   wispkey status
   wispkey list
   ```

6. **Configure MCP** (add to Cursor settings). Keep `command` as `wispkey` so the client uses the normal installed binary from `PATH`:
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

   The MCP server returns `wk_env_openai` and the env key name, never the raw env value. Start `wispkey serve` with the same `WISPKEY_SIDELOAD_OPENAI` variable when the proxy needs to substitute that token.

After setup, all API requests routed through `HTTP_PROXY=http://localhost:7700` will automatically have wisp tokens swapped for real credentials.
