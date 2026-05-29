---
name: wispkey-proxy-setup
description: Set up the WispKey proxy for a project. Use when the user wants to configure the proxy, connect an app to WispKey, set up HTTP_PROXY, or integrate wisp tokens into their development workflow.
---

# WispKey Proxy Setup

## Prerequisites

1. WispKey installed (`cargo install --path .` or binary in PATH)
2. Vault initialized: `wispkey init`
3. At least one credential stored: `wispkey add ...`

## Start the Proxy

```bash
wispkey serve
```

Default: `http://localhost:7700`. Custom port: `wispkey serve --port 8800`.

## Configure Your Project

### Shell / CLI tools
```bash
export HTTP_PROXY=http://localhost:7700
```

`HTTPS_PROXY` uses CONNECT tunneling, which is blind and cannot replace `wk_*` tokens inside TLS. For HTTPS requests that need token substitution, use reverse proxy mode with `X-Target-Url`.

### Node.js
For HTTPS token substitution, call the local reverse proxy target:
```typescript
const response = await fetch("http://localhost:7700", {
  headers: {
    "X-Target-Url": "https://api.example.com/test",
    "Authorization": "Bearer wk_your_token_here"
  }
});
```

### Python
```python
requests.get("http://localhost:7700", headers={
    "X-Target-Url": "https://api.example.com/test",
    "Authorization": "Bearer wk_your_token_here",
})
```

### Docker Compose
```yaml
services:
  app:
    environment:
      - HTTP_PROXY=http://host.docker.internal:7700
```

## MCP Integration (Cursor / Claude Code)

Add to your MCP config:
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

The agent can then call:
- `wispkey_list` -- see available credentials
- `wispkey_get_token` -- get a wisp token by name
- `wispkey_proxy_status` -- check proxy health

## Verify Setup

```bash
# Check status
wispkey status

# Test an HTTPS proxied request that swaps the wisp token
curl http://localhost:7700 \
  -H "X-Target-Url: https://api.example.com/test" \
  -H "Authorization: Bearer wk_your_token_here"

# Check the audit log
wispkey log --last 5
```

## Desktop App (Optional)

The WispKey Desktop app visualizes credentials and audit logs. It runs the local `wispkey --format json ...` CLI through Tauri commands and reads proxy runtime state from WispKey discovery metadata.
