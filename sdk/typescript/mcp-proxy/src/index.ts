#!/usr/bin/env node
/**
 * Clampd MCP Proxy — standalone proxy that wraps any MCP server with
 * Clampd's full security pipeline.
 *
 * Users connect Claude Desktop (or any MCP client) to this proxy via SSE.
 * The proxy intercepts every tool call, classifies it through ag-gateway,
 * and only forwards allowed calls to the upstream MCP server.
 *
 * Usage:
 *   clampd-mcp-proxy \
 *     --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \
 *     --gateway http://localhost:8080 \
 *     --api-key ag_test_acme_demo_2026 \
 *     --agent-id b0000001-0000-0000-0000-000000000001 \
 *     --port 3003
 *
 * Claude Desktop config (mcpServers):
 *   {
 *     "filesystem": {
 *       "url": "http://localhost:3003/sse"
 *     }
 *   }
 */

import { parseArgs } from "node:util";
import { startProxy } from "./proxy.js";
import { startFleet } from "./fleet.js";

// ── CLI argument parsing ──────────────────────────────────────────────

function parseCli() {
  const { values } = parseArgs({
    options: {
      upstream: { type: "string", short: "u" },
      gateway: { type: "string", short: "g" },
      "api-key": { type: "string", short: "k" },
      "agent-id": { type: "string", short: "a" },
      port: { type: "string", short: "p" },
      secret: { type: "string", short: "s" },
      "dry-run": { type: "boolean", default: false },
      "scan-input": { type: "boolean", default: false },
      "scan-output": { type: "boolean", default: false },
      "check-response": { type: "boolean", default: false },
      "demo-panel": { type: "boolean", default: false },
      "fleet-config": { type: "string" },
      verbose: { type: "boolean", short: "v", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
    strict: true,
  });

  if (values.help) {
    printUsage();
    process.exit(0);
  }

  // Fleet mode — start multiple proxies from config file
  if (values["fleet-config"]) {
    return { fleetConfig: values["fleet-config"], verbose: values.verbose! };
  }

  // CLI args take priority, then env vars, then defaults
  const upstream = values.upstream ?? process.env.UPSTREAM_MCP;
  const gateway = values.gateway ?? process.env.AG_GATEWAY_URL ?? "http://localhost:8080";
  const apiKey = values["api-key"] ?? process.env.AG_API_KEY ?? "clmpd_demo_key";
  const agentId = values["agent-id"] ?? process.env.AG_AGENT_ID;
  const port = values.port ?? process.env.PORT ?? "3003";
  const secret = values.secret ?? process.env.CLAMPD_AGENT_SECRET ?? process.env.JWT_SECRET;

  // Feature flags: CLI flag OR env var
  const scanInput = values["scan-input"] || process.env.CLAMPD_SCAN_INPUT === "true";
  const scanOutput = values["scan-output"] || process.env.CLAMPD_SCAN_OUTPUT === "true";
  const checkResponse = values["check-response"] || process.env.CLAMPD_CHECK_RESPONSE === "true";
  const demoPanel = values["demo-panel"] || process.env.CLAMPD_DEMO_PANEL === "true";

  if (!upstream) {
    console.error("Error: --upstream is required (command to spawn the MCP server)");
    console.error("       Set via --upstream flag or UPSTREAM_MCP env var");
    printUsage();
    process.exit(1);
  }

  if (!agentId) {
    console.error("Error: --agent-id is required");
    console.error("       Set via --agent-id flag or AG_AGENT_ID env var");
    printUsage();
    process.exit(1);
  }

  return {
    upstream,
    gateway,
    apiKey,
    agentId,
    port: parseInt(port, 10),
    secret,
    dryRun: values["dry-run"]!,
    scanInput,
    scanOutput,
    checkResponse,
    demoPanel,
    verbose: values.verbose!,
  };
}

function printUsage(): void {
  console.log(`
Clampd MCP Proxy — wraps any MCP server with Clampd security

Usage:
  clampd-mcp-proxy --upstream <command> --agent-id <uuid> [options]

Required:
  --upstream, -u      Command to spawn the upstream MCP server
                      Example: "npx -y @modelcontextprotocol/server-filesystem /tmp"
  --agent-id, -a      Clampd agent UUID

Options:
  --gateway, -g       Clampd gateway URL (default: http://localhost:8080)
  --api-key, -k       Clampd API key (default: clmpd_demo_key)
  --port, -p          Port to listen on (default: 3003)
  --secret, -s        Signing secret (default: CLAMPD_AGENT_SECRET or JWT_SECRET env var)
  --dry-run           Classify but never forward (uses /v1/verify)
  --scan-input        Scan tool arguments for prompt injection / PII / secrets
  --scan-output       Scan tool responses for PII / secrets leakage
  --check-response    Validate responses against granted scope token
  --demo-panel        Show attack demo panel in dashboard
  --fleet-config      Path to fleet config JSON (multi-agent mode)
  --verbose, -v       Enable debug logging
  --help, -h          Show this help

Environment Variables:
  UPSTREAM_MCP          Upstream MCP server command
  AG_GATEWAY_URL        Gateway URL
  AG_API_KEY            API key
  AG_AGENT_ID           Agent UUID
  CLAMPD_AGENT_SECRET   Agent signing secret (ags_...)
  JWT_SECRET            Global JWT signing secret (fallback)
  CLAMPD_SCAN_INPUT     Enable input scanning (true/false)
  CLAMPD_SCAN_OUTPUT    Enable output scanning (true/false)
  CLAMPD_CHECK_RESPONSE Enable response checking (true/false)

Claude Desktop config:
  {
    "mcpServers": {
      "filesystem": {
        "url": "http://localhost:3003/sse"
      }
    }
  }
`);
}

// ── Main ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseCli();

  // Fleet mode: start multiple proxies from config file
  if ("fleetConfig" in args) {
    const { setVerbose } = await import("./logger.js");
    if (args.verbose) setVerbose(true);
    await startFleet(args.fleetConfig as string);
    return;
  }

  await startProxy({
    upstreamCommand: args.upstream,
    gatewayUrl: args.gateway,
    apiKey: args.apiKey,
    agentId: args.agentId,
    port: args.port,
    secret: args.secret,
    dryRun: args.dryRun,
    scanInputEnabled: args.scanInput,
    scanOutputEnabled: args.scanOutput,
    checkResponse: args.checkResponse,
    demoPanel: args.demoPanel,
    verbose: args.verbose,
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
