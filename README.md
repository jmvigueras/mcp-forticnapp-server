# FortiCNAPP MCP Server

MCP server for managing Fortinet FortiCNAPP (Cloud Native Application Protection Platform) via AI agents. Built with FastMCP, deployed as a container.

FortiCNAPP (powered by Lacework) provides cloud security capabilities including vulnerability scanning, agent management, and compliance monitoring.

## Tools

| Tool | Description |
|------|-------------|
| `cnapp_health_check` | Check FortiCNAPP service health and connectivity |
| `cnapp_validate_config` | Validate configuration settings and credentials |
| `cnapp_get_agent_tokens` | Retrieve agent access tokens |
| `cnapp_scan_image_vulnerabilities` | Scan container images for vulnerabilities |

Every tool accepts optional `cnapp_key_id`, `cnapp_key_secret`, and `cnapp_base_url` parameters. If not provided, the server reads from environment variables. Per-call parameters override environment variables.

## Connect from Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "forticnapp": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp-forticnapp.fortidemoscloud.com/mcp"
      ]
    }
  }
}
```

## Connect from Gemini CLI

Add to your Gemini settings (`~/.gemini/settings.json`):

```json
{
  "mcpServers": {
    "forticnapp": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp-forticnapp.fortidemoscloud.com/mcp"
      ]
    }
  }
}
```

## Connect from Kiro / VS Code

Add to `.kiro/settings/mcp.json` or equivalent:

```json
{
  "mcpServers": {
    "forticnapp": {
      "url": "https://mcp-forticnapp.fortidemoscloud.com/mcp"
    }
  }
}
```

## Test with curl

```bash
# 1. Initialize session and capture Mcp-Session-Id from headers
export SESSION_ID=$(curl -s -i -X POST https://mcp-forticnapp.fortidemoscloud.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-curl","version":"1.0"}}}' \
  | grep -i "mcp-session-id" | awk '{print $2}' | tr -d '\r')

echo "Session ID: $SESSION_ID"

# 2. List tools using the captured Session ID
curl -s -X POST https://mcp-forticnapp.fortidemoscloud.com/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# 3. Call a tool (health check)
curl -s -X POST https://mcp-forticnapp.fortidemoscloud.com/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cnapp_health_check","arguments":{"cnapp_key_id":"YOUR_KEY_ID","cnapp_key_secret":"YOUR_KEY_SECRET","cnapp_base_url":"https://youraccount.lacework.net"}}}'

# 4. Scan image vulnerabilities
curl -s -X POST https://mcp-forticnapp.fortidemoscloud.com/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cnapp_scan_image_vulnerabilities","arguments":{"image_digest":"sha256:abc123...","cnapp_key_id":"YOUR_KEY_ID","cnapp_key_secret":"YOUR_KEY_SECRET"}}}'
```

## Run locally

```bash
# Docker (with credentials from environment)
export FORTICNAPP_KEY_ID="your_key_id"
export FORTICNAPP_KEY_SECRET="your_key_secret"
export FORTICNAPP_BASE_URL="youraccount.lacework.net"
docker-compose up --build -d

# Or directly
uv sync
FORTICNAPP_KEY_ID="your_key_id" \
FORTICNAPP_KEY_SECRET="your_key_secret" \
FORTICNAPP_BASE_URL="youraccount.lacework.net" \
uv run uvicorn app.server:app --host 0.0.0.0 --port 8000
```

Server available at `http://localhost:8000/mcp` with health check at `/health`.

## Deploy to Kubernetes

```bash
kubectl apply -f k8s-deployment.yaml
```

Exposes on NodePort 30083. Image: `jviguerasfortinet/mcp-forticnapp-server:v1.0.0`

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FORTICNAPP_KEY_ID` | Yes | — | Lacework API key ID |
| `FORTICNAPP_KEY_SECRET` | Yes | — | Lacework API key secret (X-LW-UAKS value) |
| `FORTICNAPP_BASE_URL` | No | `lwintseemea-eu.lacework.net` | Lacework API base URL or FQDN. Can be a full URL (`https://myaccount.lacework.net`) or just the FQDN (`myaccount.lacework.net`) — `https://` is auto-prepended if missing. |

## Tool Parameters

### cnapp_health_check / cnapp_validate_config / cnapp_get_agent_tokens

| Parameter | Required | Description |
|-----------|----------|-------------|
| `cnapp_key_id` | No | FortiCNAPP API key ID (uses `FORTICNAPP_KEY_ID` env var if not provided) |
| `cnapp_key_secret` | No | FortiCNAPP API key secret (uses `FORTICNAPP_KEY_SECRET` env var if not provided) |
| `cnapp_base_url` | No | FortiCNAPP API base URL or FQDN (e.g., `myaccount.lacework.net`). `https://` is auto-prepended if missing. Uses `FORTICNAPP_BASE_URL` env var if not provided. |

### cnapp_scan_image_vulnerabilities

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `image_digest` | Yes | — | Docker image digest (e.g., sha256:abc123...) |
| `cnapp_key_id` | No | — | FortiCNAPP API key ID |
| `cnapp_key_secret` | No | — | FortiCNAPP API key secret |
| `cnapp_base_url` | No | — | FortiCNAPP API base URL or FQDN. `https://` is auto-prepended if missing. |
| `days_back` | No | 3 | Number of days to look back for scan data |
| `deduplicate` | No | true | Remove duplicate vulnerabilities across layers |

## Authentication

The server uses Lacework bearer token authentication:

1. **Token Generation**: Uses `FORTICNAPP_KEY_SECRET` (X-LW-UAKS header) and `FORTICNAPP_KEY_ID` to request bearer tokens from `/api/v2/access/tokens`
2. **Token Caching**: Automatically caches tokens and refreshes before expiration (with 60s buffer)
3. **API Calls**: All Lacework API calls use the cached bearer token in the `Authorization: Bearer <token>` header
4. **Retry Logic**: Automatic retry with exponential backoff for transient failures
5. **URL Normalization**: `FORTICNAPP_BASE_URL` accepts either a full URL (`https://myaccount.lacework.net`) or just the FQDN (`myaccount.lacework.net`) — the `https://` scheme is always auto-prepended if missing

## License

MIT
