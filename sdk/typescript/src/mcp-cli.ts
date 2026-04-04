#!/usr/bin/env node
/**
 * CLI entry point for the Clampd MCP proxy server.
 *
 * Usage:
 *   npx tsx sdk/typescript/src/mcp-cli.ts \
 *     --downstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \
 *     --agent-id "b0000000-0000-0000-0000-000000000001" \
 *     --gateway "http://localhost:8080"
 *
 * Options:
 *   --downstream <cmd>   Command to spawn the downstream MCP server (required)
 *   --agent-id <id>      Clampd agent ID (required)
 *   --gateway <url>      Clampd gateway URL (default: http://localhost:8080)
 *   --api-key <key>      Gateway API key (default: clmpd_demo_key)
 *   --timeout <ms>       Request timeout in milliseconds (default: 30000)
 *   --dry-run            Use /v1/verify instead of /v1/proxy (no forwarding)
 *   --help               Show this help message
 */

import { ClampdMCPProxy } from "./mcp-server.js";

// ── Argument parsing ──────────────────────────────────────────────────

interface ParsedArgs {
  downstream: string;
  agentId: string;
  gateway: string;
  apiKey: string;
  timeout: number;
  dryRun: boolean;
  help: boolean;
}

function printUsage(): void {
  const usage = `
Clampd MCP Proxy — Route MCP tool calls through the Clampd security pipeline.

USAGE:
  npx tsx src/mcp-cli.ts --downstream <cmd> --agent-id <id> [options]

REQUIRED:
  --downstream <cmd>   Command to spawn the downstream MCP server.
                        The command string is split on whitespace; the first
                        token is the executable and the rest are arguments.
                        Example: "npx -y @modelcontextprotocol/server-filesystem /tmp"

  --agent-id <id>      Clampd agent identity (UUID).

OPTIONS:
  --gateway <url>      Clampd gateway URL (default: http://localhost:8080)
  --api-key <key>      Gateway API key (default: clmpd_demo_key)
  --timeout <ms>       HTTP request timeout in milliseconds (default: 30000)
  --dry-run            Evaluate policies via /v1/verify without forwarding
                        the call to the downstream server.
  --help               Show this help message and exit.

EXAMPLES:
  # Guard a filesystem MCP server
  npx tsx src/mcp-cli.ts \\
    --downstream "npx -y @modelcontextprotocol/server-filesystem /tmp" \\
    --agent-id "b0000000-0000-0000-0000-000000000001"

  # Dry-run mode against a custom gateway
  npx tsx src/mcp-cli.ts \\
    --downstream "node my-tool-server.js" \\
    --agent-id "b0000000-0000-0000-0000-000000000001" \\
    --gateway "https://clampd.example.com" \\
    --dry-run
`.trim();

  process.stderr.write(usage + "\n");
}

function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = {
    downstream: "",
    agentId: "",
    gateway: "http://localhost:8080",
    apiKey: "clmpd_demo_key",
    timeout: 30_000,
    dryRun: false,
    help: false,
  };

  // Skip node executable and script path
  const raw = argv.slice(2);
  let i = 0;

  while (i < raw.length) {
    const token = raw[i];

    switch (token) {
      case "--downstream":
        i++;
        if (i >= raw.length) {
          fatal("--downstream requires a value");
        }
        args.downstream = raw[i];
        break;

      case "--agent-id":
        i++;
        if (i >= raw.length) {
          fatal("--agent-id requires a value");
        }
        args.agentId = raw[i];
        break;

      case "--gateway":
        i++;
        if (i >= raw.length) {
          fatal("--gateway requires a value");
        }
        args.gateway = raw[i];
        break;

      case "--api-key":
        i++;
        if (i >= raw.length) {
          fatal("--api-key requires a value");
        }
        args.apiKey = raw[i];
        break;

      case "--timeout":
        i++;
        if (i >= raw.length) {
          fatal("--timeout requires a value");
        }
        {
          const parsed = parseInt(raw[i], 10);
          if (Number.isNaN(parsed) || parsed <= 0) {
            fatal(`--timeout must be a positive integer, got: ${raw[i]}`);
          }
          args.timeout = parsed;
        }
        break;

      case "--dry-run":
        args.dryRun = true;
        break;

      case "--help":
      case "-h":
        args.help = true;
        break;

      default:
        fatal(`Unknown argument: ${token}\nRun with --help for usage.`);
    }

    i++;
  }

  return args;
}

function fatal(message: string): never {
  process.stderr.write(`Error: ${message}\n`);
  process.exit(1);
}

// ── Main ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help) {
    printUsage();
    process.exit(0);
  }

  // Validate required args
  if (!args.downstream) {
    fatal("--downstream is required. Run with --help for usage.");
  }
  if (!args.agentId) {
    fatal("--agent-id is required. Run with --help for usage.");
  }

  // Split the downstream command string into command + args.
  // The first token is the executable; the rest are arguments.
  const parts = args.downstream.trim().split(/\s+/);
  const downstreamCommand = parts[0];
  const downstreamArgs = parts.slice(1);

  const proxy = new ClampdMCPProxy({
    gatewayUrl: args.gateway,
    agentId: args.agentId,
    apiKey: args.apiKey,
    downstreamCommand,
    downstreamArgs,
    timeoutMs: args.timeout,
    dryRun: args.dryRun,
  });

  // Handle termination gracefully
  const shutdown = () => {
    process.stderr.write("[clampd-mcp] Shutting down...\n");
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  try {
    await proxy.start();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    fatal(`Failed to start Clampd MCP proxy: ${message}`);
  }
}

main();
