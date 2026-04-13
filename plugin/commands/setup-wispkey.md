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

6. **Configure MCP** (add to Cursor settings):
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

After setup, all API requests routed through `HTTP_PROXY=http://localhost:7700` will automatically have wisp tokens swapped for real credentials.
