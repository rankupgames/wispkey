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
export HTTPS_PROXY=http://localhost:7700
```

### Node.js
Install `https-proxy-agent` and configure fetch/axios:
```typescript
import { HttpsProxyAgent } from "https-proxy-agent";
const agent = new HttpsProxyAgent("http://localhost:7700");
```

### Python
```python
proxies = {"http": "http://localhost:7700", "https": "http://localhost:7700"}
requests.get(url, headers=headers, proxies=proxies)
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

# Test a proxied request (should swap the wisp token)
HTTP_PROXY=http://localhost:7700 curl -H "Authorization: Bearer wk_your_token_here" https://api.example.com/test

# Check the audit log
wispkey log --last 5
```

## Desktop App (Optional)

The WispKey Desktop app visualizes credentials and audit logs. It connects to the same proxy management API at `http://localhost:7700/api/`.
