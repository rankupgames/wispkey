---
name: wispkey-proxy-setup
description: Set up the WispKey proxy for a project. Use when the user wants to configure the proxy, connect an app to WispKey, set up HTTP_PROXY, or integrate wisp tokens into their development workflow.
---

# WispKey Proxy Setup

## Prerequisites

1. WispKey installed normally (`cargo install --path . --locked`, package manager, or binary in PATH)
2. Vault initialized with `wispkey init` for vault-backed credentials, or `WISPKEY_SIDELOAD_<SLUG>` set for sideload-only use
3. At least one vault credential stored with `wispkey add ...`, or one sideload env var available to both MCP and proxy
4. The credential's project selected with `wispkey project use <project>`, unless `serve --all-projects` is intentional

## Start the Proxy

```bash
wispkey serve
```

Default: `http://localhost:7700`. Custom port: `wispkey serve --port 8800`.

For multi-instance deployments, use one or more explicit listeners:
```bash
wispkey serve \
  --listen tcp://127.0.0.1:7700 \
  --listen unix:/run/wispkey/proxy.sock
```

Unix domain socket, feature-gated Linux vsock, Firecracker UDS-backed vsock, and non-loopback TCP listeners require per-request instance identity by default. Loopback TCP keeps the trusted-local default unless `--require-identity` is set.

For sideload-only proxy use, launch with the same sideload env var that the MCP server uses:
```bash
WISPKEY_SIDELOAD_OPENAI="$OPENAI_API_KEY" wispkey serve
```

The agent still receives only `wk_env_openai`; the raw sideload value stays in the WispKey process environment.

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
    "X-Target-Url": "https://api.example.com/test?api_key=wk_your_token_here",
    "Authorization": "Bearer wk_your_token_here"
  }
});
```

### Python
```python
requests.get("http://localhost:7700", headers={
    "X-Target-Url": "https://api.example.com/test?api_key=wk_your_token_here",
    "Authorization": "Bearer wk_your_token_here",
})
```

Reverse proxy mode replaces wisp tokens in request headers, supported text bodies, and the query string inside `X-Target-Url`.

Agent-scoped policies fail closed when no trusted agent identity is available. Today the proxy does not have a trusted agent identity source, so `agent = "..."` policies still apply to proxy requests without an agent name.

### Docker Compose
```yaml
services:
  app:
    environment:
      - HTTP_PROXY=http://host.docker.internal:7700
```

## MCP Integration (Cursor / Claude Code)

Add to your MCP config. Keep `command` as `wispkey` so the client uses the normal installed binary from `PATH`, not a machine-specific absolute path:
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

For Codex-style env forwarding:
```toml
[mcp_servers.wispkey]
command = "wispkey"
args = ["mcp", "serve"]
env_vars = ["WISPKEY_SIDELOAD_OPENAI"]
```

For JSON-style configs, either launch the client with `WISPKEY_SIDELOAD_OPENAI` in its environment or add it to the MCP server `env` block. Treat `env` blocks as plaintext client config.

Do not use old fallback env names. Rename `WISPKEY_FALLBACK_<SLUG>` variables to `WISPKEY_SIDELOAD_<SLUG>` before upgrading.

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
  -H "X-Target-Url: https://api.example.com/test?api_key=wk_your_token_here" \
  -H "Authorization: Bearer wk_your_token_here"

# Check the audit log
wispkey log --last 5
```

## Desktop App (Optional)

The WispKey Desktop app visualizes credentials and audit logs. It runs the local `wispkey --format json ...` CLI through Tauri commands and reads proxy runtime state from WispKey discovery metadata.
