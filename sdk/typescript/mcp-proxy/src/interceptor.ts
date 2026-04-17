/**
 * Gateway communication - classifies tool calls, scans input/output,
 * and validates responses through ag-gateway.
 *
 * This is the security boundary: every MCP tool call passes through here
 * before reaching the upstream server.
 */

import { createHmac, createHash } from "node:crypto";
import { log } from "./logger.js";

// ── Types ─────────────────────────────────────────────────────────────

export interface ClassifyResult {
  /** Whether the tool call is allowed */
  allowed: boolean;
  /** Risk score from the 9-stage pipeline (0.0 - 1.0) */
  risk_score: number;
  /** Rule IDs that matched (e.g. ["R001", "R006"]) */
  matched_rules: string[];
  /** Human-readable denial reason (when blocked) */
  denial_reason?: string;
  /** Scope granted by OPA policy */
  scope_granted?: string;
  /** Gateway request ID for audit trail */
  request_id?: string;
  /** Scope token for response validation */
  scope_token?: string;
  /** Gateway processing latency */
  latency_ms: number;
  /** Pipeline stages that were degraded */
  degraded_stages: string[];
  /** Behavioral session flags */
  session_flags: string[];
  /** Intent action: "pass", "flag", or "block" */
  action?: string;
  /** Human-readable reasoning from the rules engine */
  reasoning?: string;
}

export interface ScanResult {
  allowed: boolean;
  risk_score: number;
  matched_rules: string[];
  denial_reason?: string;
  latency_ms: number;
  pii_found?: Array<{ pii_type: string; count: number }>;
  secrets_found?: Array<{ secret_type: string; count: number }>;
}

export interface InspectResult {
  allowed: boolean;
  risk_score: number;
  matched_rules: string[];
  denial_reason?: string;
  latency_ms: number;
}

/** Tool definition from MCP listTools() */
export interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

// ── Tool descriptor hashing ──────────────────────────────────────────

/** Compute SHA-256 hex hash of a tool descriptor for rug-pull detection. */
export function computeToolDescriptorHash(tool: ToolDef): string {
  const canonical = JSON.stringify({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {},
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/** Build a lookup map of tool name → descriptor hash. */
export function buildDescriptorMap(tools: ToolDef[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const tool of tools) {
    map.set(tool.name, computeToolDescriptorHash(tool));
  }
  return map;
}

// ── JWT generation ────────────────────────────────────────────────────

function makeAgentJwt(agentId: string, secret: string): string {
  if (!secret) {
    throw new Error(
      "No JWT signing secret available. " +
      "Set JWT_SECRET env var or pass --secret flag."
    );
  }

  // Derive signing key: ags_ prefixed secrets get SHA-256 hashed
  // to match the credential_hash stored server-side in Redis.
  const signingKey = secret.startsWith("ags_")
    ? createHash("sha256").update(secret).digest("hex")
    : secret;

  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: agentId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
    iss: "clampd-mcp-proxy",
  };

  const encode = (obj: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(obj)).toString("base64url");

  const headerB64 = encode(header);
  const payloadB64 = encode(payload);
  const signature = createHmac("sha256", signingKey)
    .update(`${headerB64}.${payloadB64}`)
    .digest("base64url");

  return `${headerB64}.${payloadB64}.${signature}`;
}

// ── Shared helpers ───────────────────────────────────────────────────

function makeHeaders(apiKey: string, agentId: string, secret: string, authorizedTools?: string[]): Record<string, string> {
  const jwt = makeAgentJwt(agentId, secret);
  const h: Record<string, string> = {
    "Content-Type": "application/json",
    "X-AG-Key": apiKey,
    "Authorization": `Bearer ${jwt}`,
  };
  if (authorizedTools && authorizedTools.length > 0) {
    h["X-AG-Authorized-Tools"] = authorizedTools.join(",");
  }
  return h;
}

function baseUrl(gatewayUrl: string): string {
  return gatewayUrl.replace(/\/$/, "");
}

// ── Gateway classify ─────────────────────────────────────────────────

export async function classifyToolCall(
  gatewayUrl: string,
  apiKey: string,
  secret: string,
  agentId: string,
  toolName: string,
  params: Record<string, unknown>,
  dryRun = false,
  toolDescriptorHash?: string,
  authorizedTools?: string[],
  toolDescription?: string,
  toolParamsSchema?: string,
): Promise<ClassifyResult> {
  const endpoint = dryRun ? "/v1/verify" : "/v1/proxy";
  const url = `${baseUrl(gatewayUrl)}${endpoint}`;

  // MCP proxy handles upstream forwarding itself - use evaluate-only
  // mode (empty target_url) so the gateway runs stages 1-6 and returns
  // the allow/deny verdict without attempting to forward to mcp://.
  const body: Record<string, unknown> = {
    tool: toolName,
    params,
    target_url: "",
  };

  if (!dryRun) {
    body.prompt_context = `MCP tool call: ${toolName}`;
  }

  if (toolDescriptorHash) {
    body.tool_descriptor_hash = toolDescriptorHash;
  }
  if (toolDescription) {
    body.tool_description = toolDescription;
  }
  if (toolParamsSchema) {
    body.tool_params_schema = toolParamsSchema;
  }

  log("debug", `POST ${url} - tool=${toolName}`);

  const resp = await fetch(url, {
    method: "POST",
    headers: makeHeaders(apiKey, agentId, secret, authorizedTools),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5_000),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => `HTTP ${resp.status}`);
    throw new Error(`Gateway returned ${resp.status}: ${text}`);
  }

  const json = (await resp.json()) as Record<string, unknown>;

  return {
    allowed: json.allowed as boolean,
    risk_score: (json.risk_score as number) ?? 0,
    matched_rules: (json.matched_rules as string[]) ?? [],
    denial_reason: json.denial_reason as string | undefined,
    scope_granted: json.scope_granted as string | undefined,
    request_id: json.request_id as string | undefined,
    scope_token: json.scope_token as string | undefined,
    latency_ms: (json.latency_ms as number) ?? 0,
    degraded_stages: (json.degraded_stages as string[]) ?? [],
    session_flags: (json.session_flags as string[]) ?? [],
    action: json.action as string | undefined,
    reasoning: json.reasoning as string | undefined,
  };
}

// ── Input scanning ───────────────────────────────────────────────────

export async function scanInput(
  gatewayUrl: string,
  apiKey: string,
  secret: string,
  agentId: string,
  text: string,
): Promise<ScanResult> {
  const url = `${baseUrl(gatewayUrl)}/v1/scan-input`;

  log("debug", `POST ${url} - scan-input (${text.length} chars)`);

  const resp = await fetch(url, {
    method: "POST",
    headers: makeHeaders(apiKey, agentId, secret),
    body: JSON.stringify({ text }),
    signal: AbortSignal.timeout(5_000),
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => `HTTP ${resp.status}`);
    throw new Error(`scan-input returned ${resp.status}: ${body}`);
  }

  const json = (await resp.json()) as Record<string, unknown>;
  return {
    allowed: json.allowed as boolean,
    risk_score: (json.risk_score as number) ?? 0,
    matched_rules: (json.matched_rules as string[]) ?? [],
    denial_reason: json.denial_reason as string | undefined,
    latency_ms: (json.latency_ms as number) ?? 0,
  };
}

// ── Output scanning ──────────────────────────────────────────────────

export async function scanOutput(
  gatewayUrl: string,
  apiKey: string,
  secret: string,
  agentId: string,
  text: string,
  requestId?: string,
): Promise<ScanResult> {
  const url = `${baseUrl(gatewayUrl)}/v1/scan-output`;

  log("debug", `POST ${url} - scan-output (${text.length} chars)`);

  const body: Record<string, unknown> = { text };
  if (requestId) body.request_id = requestId;

  const resp = await fetch(url, {
    method: "POST",
    headers: makeHeaders(apiKey, agentId, secret),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5_000),
  });

  if (!resp.ok) {
    const respBody = await resp.text().catch(() => `HTTP ${resp.status}`);
    throw new Error(`scan-output returned ${resp.status}: ${respBody}`);
  }

  const json = (await resp.json()) as Record<string, unknown>;
  return {
    allowed: json.allowed as boolean,
    risk_score: (json.risk_score as number) ?? 0,
    matched_rules: (json.matched_rules as string[]) ?? [],
    denial_reason: json.denial_reason as string | undefined,
    latency_ms: (json.latency_ms as number) ?? 0,
    pii_found: json.pii_found as ScanResult["pii_found"],
    secrets_found: json.secrets_found as ScanResult["secrets_found"],
  };
}

// ── Response inspection ──────────────────────────────────────────────

export async function inspectResponse(
  gatewayUrl: string,
  apiKey: string,
  secret: string,
  agentId: string,
  toolName: string,
  responseData: unknown,
  requestId?: string,
  scopeToken?: string,
): Promise<InspectResult> {
  const url = `${baseUrl(gatewayUrl)}/v1/inspect`;

  log("debug", `POST ${url} - inspect response for ${toolName}`);

  const body: Record<string, unknown> = {
    tool: toolName,
    response_data: responseData,
  };
  if (requestId) body.request_id = requestId;
  if (scopeToken) body.scope_token = scopeToken;

  const resp = await fetch(url, {
    method: "POST",
    headers: makeHeaders(apiKey, agentId, secret),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5_000),
  });

  if (!resp.ok) {
    const respBody = await resp.text().catch(() => `HTTP ${resp.status}`);
    throw new Error(`inspect returned ${resp.status}: ${respBody}`);
  }

  const json = (await resp.json()) as Record<string, unknown>;
  return {
    allowed: json.allowed as boolean,
    risk_score: (json.risk_score as number) ?? 0,
    matched_rules: (json.matched_rules as string[]) ?? [],
    denial_reason: json.denial_reason as string | undefined,
    latency_ms: (json.latency_ms as number) ?? 0,
  };
}

// ── Startup tool registration ───────────────────────────────────────

export interface RegisterToolsResult {
  registered: number;
  failed: number;
  errors: Array<{ tool: string; error: string }>;
}

/**
 * Register discovered tools with the gateway at startup.
 *
 * Sends a lightweight `/v1/proxy` call (evaluate-only, target_url="") for
 * each tool with benign empty params. This triggers the shadow event pipeline
 * in ag-gateway, which ag-control picks up to auto-capture tool descriptors
 * into the `tool_descriptors` table. If the org has `auto_trust` enabled,
 * tools are auto-approved and their scopes synced to Redis - preventing
 * `tool_not_registered` (422) errors on subsequent real calls.
 *
 * Requests run in parallel with a concurrency cap to avoid overwhelming
 * the gateway. Registration is idempotent (safe to re-run on restart).
 */
export async function registerTools(
  gatewayUrl: string,
  apiKey: string,
  secret: string,
  agentId: string,
  tools: ToolDef[],
  descriptorMap: Map<string, string>,
): Promise<RegisterToolsResult> {
  const url = `${baseUrl(gatewayUrl)}/v1/proxy`;
  const toolNames = tools.map((t) => t.name);
  const result: RegisterToolsResult = { registered: 0, failed: 0, errors: [] };

  // Process in batches of 5 to avoid overwhelming the gateway
  const BATCH_SIZE = 5;
  for (let i = 0; i < tools.length; i += BATCH_SIZE) {
    const batch = tools.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (tool) => {
      const body: Record<string, unknown> = {
        tool: tool.name,
        params: {},
        target_url: "",
        prompt_context: `MCP startup registration: ${tool.name}`,
      };

      const hash = descriptorMap.get(tool.name);
      if (hash) {
        body.tool_descriptor_hash = hash;
      }
      if (tool.description) {
        body.tool_description = tool.description;
      }
      if (tool.inputSchema) {
        body.tool_params_schema = JSON.stringify(tool.inputSchema);
      }

      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: makeHeaders(apiKey, agentId, secret, toolNames),
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10_000),
        });

        if (!resp.ok) {
          const text = await resp.text().catch(() => `HTTP ${resp.status}`);
          // 422 tool_not_registered is expected when auto_trust is off -
          // the shadow event was still emitted, so discovery still works.
          if (resp.status === 422) {
            result.registered++;
            return;
          }
          result.failed++;
          result.errors.push({ tool: tool.name, error: `${resp.status}: ${text}` });
          return;
        }

        result.registered++;
      } catch (err: unknown) {
        result.failed++;
        result.errors.push({
          tool: tool.name,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    });

    await Promise.all(promises);
  }

  return result;
}
