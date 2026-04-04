# @clampd/mcp-proxy

Standalone MCP proxy that wraps **any** MCP server with Clampd's 9-stage security pipeline. Connect Claude Desktop, Cursor, or any MCP client to this proxy instead of directly to an MCP server. Every tool call is classified through ag-gateway — dangerous calls are blocked before they reach the tool.

## Quick Start

```bash
# Install
cd sdk/typescript/mcp-proxy && npm install

# Run (wraps the filesystem MCP server)
npx tsx src/index.ts \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --gateway http://localhost:8080 \
  --agent-id b0000001-0000-0000-0000-000000000001 \
  --api-key ag_test_acme_demo_2026

# Open the dashboard
open http://localhost:3003
```

## Claude Desktop Configuration

Add to your Claude Desktop `mcpServers` config:

```json
{
  "mcpServers": {
    "filesystem": {
      "url": "http://localhost:3003/sse"
    }
  }
}
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET` | JWT signing secret for agent auth | (none) |

## CLI Options

```
--upstream, -u    Command to spawn the upstream MCP server (required)
--agent-id, -a    Clampd agent UUID (required)
--gateway, -g     Clampd gateway URL (default: http://localhost:8080)
--api-key, -k     Clampd API key (default: clmpd_demo_key)
--port, -p        Port to listen on (default: 3003)
--secret, -s      JWT signing secret
--dry-run         Classify but never forward to upstream
--verbose, -v     Enable debug logging
```

## Architecture

```
Claude Desktop / Cursor / Any MCP Client
    |
    | MCP protocol (SSE transport)
    v
Clampd MCP Proxy (:3003)
    |
    +---> GET /sse      -- MCP SSE endpoint (client connects here)
    +---> GET /          -- Live dashboard (blocked/allowed in real-time)
    +---> GET /health    -- Health check JSON
    +---> GET /events    -- Dashboard SSE stream (live updates)
    |
    | For each tool call:
    |   1. Extract tool_name + params from MCP call_tool request
    |   2. POST to ag-gateway /v1/proxy { tool, params, target_url }
    |   3. If gateway says BLOCK -> return MCP error to client
    |   4. If gateway says ALLOW -> forward to upstream MCP server
    |
    v
Upstream MCP Server (filesystem, database, github, shell, etc.)
    (spawned as child process, communicates via stdio)
```

## Deployment

### Docker

```bash
docker build -t clampd-mcp-proxy .
docker run -p 3003:3003 clampd-mcp-proxy \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --gateway http://host.docker.internal:8080 \
  --agent-id b0000001-0000-0000-0000-000000000001
```

### npm global install

```bash
npm install -g @clampd/mcp-proxy
clampd-mcp-proxy --upstream "..." --agent-id "..."
```

### npx (no install)

```bash
npx @clampd/mcp-proxy --upstream "..." --agent-id "..."
```
