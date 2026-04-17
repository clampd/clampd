/**
 * ClampdMCPProxy - MCP proxy server that routes all tool calls through
 * the Clampd 9-stage security pipeline before reaching the downstream
 * MCP tool server.
 *
 * Architecture:
 *   LLM Client  <--stdio-->  ClampdMCPProxy  <--stdio-->  Downstream MCP Server
 *                                  |
 *                            Clampd Gateway
 *                           (/v1/proxy or /v1/verify)
 *
 * Every `tools/call` is intercepted, sent to the Clampd gateway for
 * classification, policy-checking, scoping, and audit logging. Only if
 * the gateway allows the call does it proceed to the downstream server.
 *
 * Requires @modelcontextprotocol/sdk as a peer dependency.
 */

import { makeAgentJwt } from "./auth.js";
import { withDelegation, getDelegation, getCallerAgentId, MAX_DELEGATION_DEPTH } from "./delegation.js";

// ── Types ──────────────────────────────────────────────────────────────

export interface ClampdMCPProxyOptions {
  /** Clampd gateway base URL (e.g. "http://localhost:8080") */
  gatewayUrl: string;

  /** Agent identity registered with Clampd */
  agentId: string;

  /** API key for gateway authentication */
  apiKey?: string;

  /** Command to spawn the downstream MCP server */
  downstreamCommand: string;

  /** Arguments for the downstream command */
  downstreamArgs?: string[];

  /** Environment variables for the downstream process */
  downstreamEnv?: Record<string, string>;

  /** Request timeout in milliseconds (default: 30000) */
  timeoutMs?: number;

  /**
   * Optional UUID of the parent agent connecting to this MCP server.
   * When set, the delegation chain includes the parent for full
   * cross-agent tracking (Agent A -> Agent B).
   */
  parentAgentId?: string;

  /**
   * Dry-run mode: use /v1/verify instead of /v1/proxy.
   * The call is evaluated but never actually forwarded to downstream.
   */
  dryRun?: boolean;

  /**
   * Maximum number of retries when connecting to the downstream server.
   * Downstream MCP servers spawned via stdio may take time to initialize.
   * (default: 3)
   */
  connectRetries?: number;

  /**
   * Delay between connection retries in milliseconds (default: 1000).
   */
  connectRetryDelayMs?: number;

  /** Optional JWT signing secret. Falls back to JWT_SECRET env var. */
  secret?: string;
}

/** Subset of the gateway response we rely on. */
interface GatewayResponse {
  request_id: string;
  allowed: boolean;
  risk_score: number;
  scope_granted?: string | null;
  tool_response?: unknown | null;
  denial_reason?: string | null;
  latency_ms: number;
  degraded_stages: string[];
  session_flags: string[];
}

// ── Lazy MCP SDK loader ────────────────────────────────────────────────

interface MCPModules {
  Server: typeof import("@modelcontextprotocol/sdk/server/index.js").Server;
  StdioServerTransport: typeof import("@modelcontextprotocol/sdk/server/stdio.js").StdioServerTransport;
  Client: typeof import("@modelcontextprotocol/sdk/client/index.js").Client;
  StdioClientTransport: typeof import("@modelcontextprotocol/sdk/client/stdio.js").StdioClientTransport;
  CallToolRequestSchema: typeof import("@modelcontextprotocol/sdk/types.js").CallToolRequestSchema;
  ListToolsRequestSchema: typeof import("@modelcontextprotocol/sdk/types.js").ListToolsRequestSchema;
}

async function loadMCPModules(): Promise<MCPModules> {
  try {
    const [serverMod, stdioServerMod, clientMod, stdioClientMod, typesMod] =
      await Promise.all([
        import("@modelcontextprotocol/sdk/server/index.js"),
        import("@modelcontextprotocol/sdk/server/stdio.js"),
        import("@modelcontextprotocol/sdk/client/index.js"),
        import("@modelcontextprotocol/sdk/client/stdio.js"),
        import("@modelcontextprotocol/sdk/types.js"),
      ]);

    return {
      Server: serverMod.Server,
      StdioServerTransport: stdioServerMod.StdioServerTransport,
      Client: clientMod.Client,
      StdioClientTransport: stdioClientMod.StdioClientTransport,
      CallToolRequestSchema: typesMod.CallToolRequestSchema,
      ListToolsRequestSchema: typesMod.ListToolsRequestSchema,
    };
  } catch {
    throw new Error(
      "@modelcontextprotocol/sdk is required for the MCP proxy. " +
        "Install with: npm install @modelcontextprotocol/sdk",
    );
  }
}

// ── Utility ────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function log(level: "info" | "warn" | "error", msg: string): void {
  // Write to stderr to avoid corrupting the stdio MCP transport on stdout.
  const ts = new Date().toISOString();
  process.stderr.write(`[${ts}] [clampd-mcp] [${level}] ${msg}\n`);
}

// ── Metadata filtering for directory tools (Bypass #6 fix) ──

const METADATA_TOOLS = new Set(["directory_tree", "list_directory", "list_directory_with_sizes"]);

const EXCLUDED_PATH_PATTERNS = [
  "node-compile-cache", ".npm/_cacache", "__pycache__", ".cache/pip",
  ".rustup", ".cargo/registry", ".local/share/pnpm",
];

function filterMetadataResponse(toolName: string, content: Array<{ type: string; text?: string }>): Array<{ type: string; text?: string }> {
  if (!METADATA_TOOLS.has(toolName)) return content;

  return content.map((block) => {
    if (block.type !== "text" || !block.text) return block;
    const lines = block.text.split("\n");
    const filtered = lines.filter((line) =>
      !EXCLUDED_PATH_PATTERNS.some((pat) => line.includes(pat))
    );
    return { ...block, text: filtered.join("\n") };
  });
}

// ── File content scanning for MCP write/edit tools (Bypass #1-#5 fix) ──

const DANGEROUS_EXTENSIONS = new Set([
  ".sql", ".sh", ".bash", ".zsh", ".py", ".rb", ".ps1", ".bat", ".cmd",
  ".js", ".ts", ".php", ".pl", ".lua", ".yaml", ".yml", ".json", ".xml",
  ".env", ".conf", ".cfg", ".ini", ".toml", ".log",
]);

const FILE_WRITE_TOOLS: Record<string, string> = {
  write_file: "content",
  create_file: "content",
  edit_file: "newText",
  append_file: "content",
  insert_text: "text",
};

async function scanFileContent(
  proxy: ClampdMCPProxy,
  toolName: string,
  toolArgs: Record<string, unknown>,
  logFn: (level: "info" | "warn" | "error", msg: string) => void,
): Promise<string | null> {
  const contentField = FILE_WRITE_TOOLS[toolName];
  if (!contentField) return null;

  const content = toolArgs[contentField];
  if (!content || typeof content !== "string") return null;

  const filePath = (toolArgs.path ?? toolArgs.file_path ?? "") as string;

  // Check ALL extensions in filename (double-extension bypass fix: evil.sql.jpg)
  let hasDangerousExt = false;
  if (filePath && filePath.includes(".")) {
    const filename = filePath.split("/").pop() ?? "";
    const parts = filename.toLowerCase().split(".");
    for (let i = 1; i < parts.length; i++) {
      if (DANGEROUS_EXTENSIONS.has("." + parts[i])) {
        hasDangerousExt = true;
        break;
      }
    }
  }

  // Check for suspicious non-ASCII chars (encoding evasion indicator)
  const hasSuspiciousChars = content.length <= 500 &&
    [...content.slice(0, 200)].some(c => c.charCodeAt(0) > 127);

  // Only skip for very short content with no dangerous ext and no suspicious chars
  if (!hasDangerousExt && content.length < 100 && !hasSuspiciousChars) return null;

  const ext = filePath.includes(".") ? "." + filePath.split(".").pop() : "";
  logFn("info", `Scanning ${toolName} content for ${filePath} (${content.length} bytes, ext=${ext || "unknown"})`);

  try {
    const { ClampdClient } = await import("./client.js");
    const client = new ClampdClient({
      gatewayUrl: (proxy as any).gatewayUrl,
      agentId: (proxy as any).agentId,
      apiKey: (proxy as any).apiKey,
    });
    const result = await client.scanInput(content);
    if (!result.allowed) {
      const risk = result.risk_score?.toFixed(2) ?? "N/A";
      const reason = result.denial_reason ?? "dangerous content detected";
      const rules = result.matched_rules?.join(", ") ?? "content policy violation";
      logFn("warn", `BLOCKED ${toolName} to ${filePath}: risk=${risk} reason=${reason}`);
      return (
        `[clampd] BLOCKED: ${toolName} to '${filePath}' denied.\n` +
        `Risk score: ${risk}\n` +
        `Reason: ${reason}\n` +
        `Matched rules: ${rules}\n` +
        `The file content contains dangerous patterns that violate security policy.`
      );
    }
  } catch (err) {
    logFn("warn", `Content scan failed (allowing): ${err}`);
  }

  return null;
}

// ── Proxy class ────────────────────────────────────────────────────────

export class ClampdMCPProxy {
  private readonly gatewayUrl: string;
  private readonly agentId: string;
  private readonly apiKey: string;
  private readonly jwt: string;
  private readonly downstreamCommand: string;
  private readonly downstreamArgs: string[];
  private readonly downstreamEnv: Record<string, string> | undefined;
  private readonly timeoutMs: number;
  private readonly parentAgentId: string | undefined;
  private readonly dryRun: boolean;
  private readonly connectRetries: number;
  private readonly connectRetryDelayMs: number;

  // Populated during start()
  private mcpClient: InstanceType<MCPModules["Client"]> | null = null;
  private mcpServer: InstanceType<MCPModules["Server"]> | null = null;

  constructor(opts: ClampdMCPProxyOptions) {
    this.gatewayUrl = opts.gatewayUrl.replace(/\/$/, "");
    this.agentId = opts.agentId;
    this.apiKey = opts.apiKey ?? "clmpd_demo_key";
    this.jwt = makeAgentJwt(this.agentId, { secret: opts.secret });
    this.downstreamCommand = opts.downstreamCommand;
    this.downstreamArgs = opts.downstreamArgs ?? [];
    this.downstreamEnv = opts.downstreamEnv;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.parentAgentId = opts.parentAgentId;
    this.dryRun = opts.dryRun ?? false;
    this.connectRetries = opts.connectRetries ?? 3;
    this.connectRetryDelayMs = opts.connectRetryDelayMs ?? 1_000;
  }

  // ── Public API ─────────────────────────────────────────────────────

  /**
   * Start the proxy: connect to downstream MCP server, discover its
   * tools, then serve them on stdio to the upstream LLM client with
   * Clampd interception on every call.
   */
  async start(): Promise<void> {
    const mcp = await loadMCPModules();

    // 1. Connect to downstream MCP server
    log("info", `Spawning downstream: ${this.downstreamCommand} ${this.downstreamArgs.join(" ")}`);

    const clientTransport = new mcp.StdioClientTransport({
      command: this.downstreamCommand,
      args: this.downstreamArgs,
      env: this.downstreamEnv
        ? { ...process.env, ...this.downstreamEnv } as Record<string, string>
        : undefined,
    });

    this.mcpClient = new mcp.Client(
      { name: "clampd-mcp-proxy", version: "0.1.0" },
      { capabilities: {} },
    );

    await this.connectWithRetry(clientTransport);
    log("info", "Connected to downstream MCP server");

    // 2. Discover downstream tools
    const toolsResult = await this.mcpClient.listTools();
    const downstreamTools = toolsResult.tools;
    log("info", `Discovered ${downstreamTools.length} tool(s) from downstream`);

    for (const tool of downstreamTools) {
      log("info", `  - ${tool.name}: ${(tool.description ?? "").slice(0, 80)}`);
    }

    // 3. Create the upstream-facing MCP server
    const modeLabel = this.dryRun ? "dry-run (verify)" : "proxy";
    this.mcpServer = new mcp.Server(
      {
        name: "clampd-mcp-proxy",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    // 4. Register listTools handler - mirror downstream tools
    this.mcpServer.setRequestHandler(
      mcp.ListToolsRequestSchema,
      async () => {
        return { tools: downstreamTools };
      },
    );

    // 5. Register callTool handler - intercept via Clampd gateway
    const client = this.mcpClient;
    const proxyRef = this;
    this.mcpServer.setRequestHandler(
      mcp.CallToolRequestSchema,
      async (request: { params: { name: string; arguments?: Record<string, unknown> } }) => {
        const toolName = request.params.name;
        const toolArgs = (request.params.arguments ?? {}) as Record<string, unknown>;

        log("info", `Tool call intercepted: ${toolName}`);

        // -- Content scanning for file-write MCP tools (Bypass #1-#5 fix) --
        const contentDenial = await scanFileContent(proxyRef, toolName, toolArgs, log);
        if (contentDenial) {
          return {
            content: [{ type: "text" as const, text: contentDenial }],
            isError: false,
          };
        }

        // Wrap the entire tool call in delegation context so the gateway
        // call includes caller_agent_id, delegation_chain, and trace_id.
        // If parentAgentId is set, nest two delegation scopes to build
        // the full parent -> this agent chain.
        const handleWithDelegation = async () => {
          // Stage A: Call Clampd gateway (delegation context is active)
          let gatewayResult: GatewayResponse;
          try {
            gatewayResult = await proxyRef.callGateway(toolName, toolArgs);
          } catch (err: unknown) {
            const message = err instanceof Error ? err.message : String(err);
            log("error", `Gateway error for ${toolName}: ${message}`);
            return {
              content: [
                {
                  type: "text" as const,
                  text: `[CLAMPD ERROR] Gateway unreachable: ${message}`,
                },
              ],
              isError: true,
            };
          }

          log(
            "info",
            `Gateway verdict for ${toolName}: allowed=${gatewayResult.allowed}, ` +
              `risk=${gatewayResult.risk_score.toFixed(2)}, ` +
              `latency=${gatewayResult.latency_ms}ms`,
          );

          // Stage B: If blocked, return denial
          if (!gatewayResult.allowed) {
            const reason = gatewayResult.denial_reason ?? "Policy violation";
            const risk = gatewayResult.risk_score.toFixed(2);
            log("warn", `BLOCKED ${toolName}: ${reason} (risk=${risk})`);

            return {
              content: [
                {
                  type: "text" as const,
                  text: `[BLOCKED by Clampd] ${reason} (risk=${risk})`,
                },
              ],
              isError: false,
            };
          }

          // Stage C: If dry-run mode, return the verification result
          if (proxyRef.dryRun) {
            return {
              content: [
                {
                  type: "text" as const,
                  text:
                    `[CLAMPD DRY-RUN] Tool ${toolName} ALLOWED ` +
                    `(risk=${gatewayResult.risk_score.toFixed(2)}, ` +
                    `scope=${gatewayResult.scope_granted ?? "none"}, ` +
                    `latency=${gatewayResult.latency_ms}ms). ` +
                    `Call was NOT forwarded to downstream.`,
                },
              ],
              isError: false,
            };
          }

          // Stage D: Forward to downstream MCP server
          try {
            const downstreamResult = await client.callTool({
              name: toolName,
              arguments: toolArgs,
            });

            log("info", `Downstream returned for ${toolName}`);

            // Bypass #6: Filter metadata leaks from directory listing tools
            if (METADATA_TOOLS.has(toolName) && downstreamResult?.content) {
              downstreamResult.content = filterMetadataResponse(
                toolName,
                downstreamResult.content as Array<{ type: string; text?: string }>,
              );
            }

            // Pass through the downstream response (supports TextContent,
            // ImageContent, EmbeddedResource, and any future content types)
            return downstreamResult;
          } catch (err: unknown) {
            const message = err instanceof Error ? err.message : String(err);
            log("error", `Downstream error for ${toolName}: ${message}`);
            return {
              content: [
                {
                  type: "text" as const,
                  text: `[CLAMPD ERROR] Downstream tool failed: ${message}`,
                },
              ],
              isError: true,
            };
          }
        };

        // Build the delegation-wrapped handler. If parentAgentId is set,
        // nest two withDelegation calls to get [parent, this] chain.
        let result;
        if (proxyRef.parentAgentId) {
          result = await withDelegation(proxyRef.parentAgentId, () =>
            withDelegation(proxyRef.agentId, handleWithDelegation),
          );
        } else {
          result = await withDelegation(proxyRef.agentId, handleWithDelegation);
        }
        return result;
      },
    );

    // 6. Connect the server to stdio for the upstream LLM client
    const serverTransport = new mcp.StdioServerTransport();
    await this.mcpServer.connect(serverTransport);

    log("info", `Clampd MCP proxy running (mode: ${modeLabel})`);
    log("info", `Gateway: ${this.gatewayUrl}`);
    log("info", `Agent: ${this.agentId}`);
  }

  // ── Internal: Gateway communication ────────────────────────────────

  /**
   * Call the Clampd gateway to evaluate a tool invocation.
   * Uses /v1/proxy in normal mode, /v1/verify in dry-run mode.
   */
  private async callGateway(
    tool: string,
    params: Record<string, unknown>,
  ): Promise<GatewayResponse> {
    const endpoint = this.dryRun ? "/v1/verify" : "/v1/proxy";
    const url = `${this.gatewayUrl}${endpoint}`;

    // MCP proxy handles downstream forwarding itself (Stage C below),
    // so we use evaluate-only mode (empty target_url) - same as the SDK.
    // A non-empty target_url would push the gateway into Stages 7-8
    // (token exchange + HTTP forward to "mcp://downstream/...") which fails.
    const body: Record<string, unknown> = {
      tool,
      params,
      target_url: "",
    };

    if (!this.dryRun) {
      body.prompt_context = `MCP tool call: ${tool}`;
    }

    // Include delegation context if present (set by withDelegation wrapper)
    const delegation = getDelegation();
    if (delegation && delegation.chain.length >= 2) {
      body.caller_agent_id = delegation.chain[delegation.chain.length - 2];
      body.delegation_chain = delegation.chain;
      body.delegation_trace_id = delegation.traceId;
    }

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.jwt}`,
        "X-AG-Key": this.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => `HTTP ${resp.status}`);
      throw new Error(`Gateway returned ${resp.status}: ${text}`);
    }

    const json = (await resp.json()) as GatewayResponse;
    return {
      ...json,
      degraded_stages: json.degraded_stages ?? [],
      session_flags: json.session_flags ?? [],
    };
  }

  // ── Internal: Downstream connection with retry ─────────────────────

  /**
   * Attempt to connect to the downstream MCP server with retries.
   * Subprocess-based MCP servers may take a moment to initialize.
   */
  private async connectWithRetry(
    transport: InstanceType<MCPModules["StdioClientTransport"]>,
  ): Promise<void> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= this.connectRetries; attempt++) {
      try {
        await this.mcpClient!.connect(transport);
        return;
      } catch (err: unknown) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < this.connectRetries) {
          log(
            "warn",
            `Downstream connection attempt ${attempt}/${this.connectRetries} failed: ` +
              `${lastError.message}. Retrying in ${this.connectRetryDelayMs}ms...`,
          );
          await sleep(this.connectRetryDelayMs);
        }
      }
    }

    throw new Error(
      `Failed to connect to downstream MCP server after ${this.connectRetries} attempt(s): ` +
        `${lastError?.message ?? "unknown error"}`,
    );
  }
}
