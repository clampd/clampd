/**
 * Clampd TypeScript SDK — Guard AI agent tool calls in 1 line.
 *
 * @example
 * ```ts
 * import clampd from "@clampd/sdk";
 *
 * // Guard OpenAI tool calls
 * const client = clampd.openai(new OpenAI(), { agentId: "my-agent" });
 *
 * // Guard Anthropic/Claude tool calls
 * const client = clampd.anthropic(new Anthropic(), { agentId: "my-agent" });
 *
 * // Guard any function
 * const safeFn = clampd.guard(myFn, { agentId: "my-agent", toolName: "db.query" });
 *
 * // Guard OpenAI tool definitions
 * const safeTools = clampd.tools(myTools, { agentId: "my-agent" });
 * ```
 */

import { createHash } from "node:crypto";
import { ClampdClient, type ClampdClientOptions, type ProxyResponse, type ScanResponse, type ScanOutputResponse } from "./client.js";
import { makeAgentJwt } from "./auth.js";
import { ClampdBlockedError, type OpenAITool } from "./interceptor.js";
import { withDelegation, getDelegation, getCallerAgentId, delegationHeaders, type DelegationContext } from "./delegation.js";
import { scanForSchemaInjection, type SchemaInjectionWarning } from "./schema-injection.js";
import { guardOpenAIStream, guardAnthropicStream } from "./stream-guard.js";

export { ClampdClient, type ClampdClientOptions, type ProxyResponse, type ScanResponse, type ScanOutputResponse } from "./client.js";
export { makeAgentJwt } from "./auth.js";
export { ClampdBlockedError, type OpenAITool } from "./interceptor.js";
export { withDelegation, getDelegation, getCallerAgentId, delegationHeaders, type DelegationContext } from "./delegation.js";
export { scanForSchemaInjection, type SchemaInjectionWarning } from "./schema-injection.js";
export { verifyScopeToken, requireScope, getCurrentScopeToken, ScopeVerificationError, withScopeToken, setScopeToken, fetchJwks, invalidateJwksCache } from "./tool-verify.js";
export type { ScopeTokenClaims } from "./tool-verify.js";
export { guardOpenAIStream, guardAnthropicStream } from "./stream-guard.js";
export type { CircuitBreakerOptions, RetryOptions } from "./client.js";

// ── Global config ─────────────────────────────────────────────────

let defaultClient: ClampdClient | null = null;
/** Per-agent client pool — each agent gets its own JWT signed with its own secret. */
const agentClients = new Map<string, ClampdClient>();
/** Per-agent secrets registered via init({ agents: {...} }) or env vars. */
const agentSecrets = new Map<string, string>();
/** Shared config from init() — gateway URL, API key. */
let sharedConfig: { gatewayUrl?: string; apiKey?: string } = {};

interface InitOptions {
  agentId: string;
  gatewayUrl?: string;
  apiKey?: string;
  secret?: string;
  /** Per-agent secrets for multi-agent setups.
   * Each agent gets its own JWT signed with its own ags_ secret.
   * Kill/rate-limit/EMA operate independently per agent.
   * @example
   * clampd.init({
   *   agentId: "orchestrator",
   *   agents: {
   *     "orchestrator": process.env.ORCHESTRATOR_SECRET,
   *     "research-agent": process.env.RESEARCHER_SECRET,
   *   }
   * });
   */
  agents?: Record<string, string | undefined>;
}

interface GuardOptions {
  agentId?: string;
  toolName: string;
  targetUrl?: string;
  failOpen?: boolean;
  checkResponse?: boolean;
}

interface WrapOptions {
  agentId?: string;
  targetUrl?: string;
  failOpen?: boolean;
  checkResponse?: boolean;
  scanInput?: boolean;
  scanOutput?: boolean;
  /** Enable stream interception for tool calls. When true, streaming tool call
   * chunks are buffered and guarded before release. Default: false.
   * When false and streaming with tools, a warning is logged. */
  guardStream?: boolean;
  schemaRegistry?: Record<string, string>;  // tool_name -> "sha256:..." hash
}

/**
 * Get or create a ClampdClient for the given agentId.
 *
 * Per-agent identity: if the agentId has a registered secret (via init({ agents })
 * or env var CLAMPD_SECRET_{agentId}), a dedicated client is created with its own
 * JWT. This means kill/rate-limit/EMA operate on THIS agent, not the init() agent.
 *
 * Fallback: if no per-agent secret exists, uses the default client from init().
 */
function getClient(opts?: { agentId?: string; gatewayUrl?: string; apiKey?: string; secret?: string }): ClampdClient {
  const agentId = opts?.agentId || process.env.CLAMPD_AGENT_ID || "";

  // Check for per-agent client (already created)
  if (agentId && agentClients.has(agentId)) {
    return agentClients.get(agentId)!;
  }

  // Check for per-agent secret (create dedicated client)
  if (agentId) {
    const envKey = `CLAMPD_SECRET_${agentId.replace(/[^a-zA-Z0-9]/g, "_")}`;
    const secret = agentSecrets.get(agentId) || process.env[envKey];

    if (secret) {
      const client = new ClampdClient({
        agentId,
        gatewayUrl: opts?.gatewayUrl || sharedConfig.gatewayUrl || process.env.CLAMPD_GATEWAY_URL,
        apiKey: opts?.apiKey || sharedConfig.apiKey || process.env.CLAMPD_API_KEY,
        secret,
      });
      agentClients.set(agentId, client);
      return client;
    }
  }

  // Fallback to default client
  if (defaultClient) return defaultClient;

  if (!agentId) {
    throw new Error(
      "No agentId provided. Call clampd.init({ agentId }) first, " +
      "or pass agentId to each function, or set CLAMPD_AGENT_ID env var."
    );
  }

  return new ClampdClient({
    agentId,
    gatewayUrl: opts?.gatewayUrl || process.env.CLAMPD_GATEWAY_URL,
    apiKey: opts?.apiKey || process.env.CLAMPD_API_KEY,
    secret: opts?.secret,
  });
}

// ── clampd.init() ─────────────────────────────────────────────────

function init(opts: InitOptions): ClampdClient {
  sharedConfig = { gatewayUrl: opts.gatewayUrl, apiKey: opts.apiKey };

  // Register per-agent secrets
  if (opts.agents) {
    for (const [id, secret] of Object.entries(opts.agents)) {
      if (secret) agentSecrets.set(id, secret);
    }
  }

  defaultClient = new ClampdClient({
    agentId: opts.agentId,
    gatewayUrl: opts.gatewayUrl,
    apiKey: opts.apiKey,
    secret: agentSecrets.get(opts.agentId) || opts.secret,
  });
  agentClients.set(opts.agentId, defaultClient);
  return defaultClient;
}

// ── Response inspection helper ────────────────────────────────────

async function inspectResponse(
  client: ClampdClient,
  tool: string,
  responseData: unknown,
  requestId: string = "",
  failOpen: boolean = false,
  scopeToken: string = "",
): Promise<void> {
  // 1. inspect — anomaly detection, scope validation
  try {
    const res = await client.inspect(tool, responseData, requestId || undefined, scopeToken || undefined);
    if (!res.allowed) {
      throw new ClampdBlockedError(res);
    }
  } catch (e) {
    if (e instanceof ClampdBlockedError) throw e;
    if (!failOpen) throw new ClampdBlockedError({
      request_id: "error", allowed: false, risk_score: 1.0,
      denial_reason: `Response inspection failed: ${e}`, latency_ms: 0,
      degraded_stages: [], session_flags: [],
    });
  }

  // 2. scan_output — PII/secrets detection on serialized text.
  // inspect checks anomalies/scope; scan_output catches sensitive data.
  try {
    const text = typeof responseData === "string"
      ? responseData
      : JSON.stringify(responseData);
    const scanRes = await client.scanOutput(text, requestId || undefined);
    if (!scanRes.allowed) {
      throw new ClampdBlockedError({
        request_id: requestId || "scan",
        allowed: false,
        risk_score: scanRes.risk_score,
        denial_reason: scanRes.denial_reason ?? "Response contains sensitive data",
        matched_rules: scanRes.matched_rules ?? [],
        latency_ms: scanRes.latency_ms ?? 0,
        degraded_stages: [],
        session_flags: [],
      });
    }
  } catch (e) {
    if (e instanceof ClampdBlockedError) throw e;
    if (!failOpen) throw new ClampdBlockedError({
      request_id: "error", allowed: false, risk_score: 1.0,
      denial_reason: `Response scan failed: ${e}`, latency_ms: 0,
      degraded_stages: [], session_flags: [],
    });
  }
}

// ── clampd.guard() — wrap any async function ──────────────────────

function guard<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => Promise<TReturn>,
  opts: GuardOptions,
): (...args: TArgs) => Promise<TReturn> {
  const client = getClient({ agentId: opts.agentId });
  const { toolName, targetUrl = "", failOpen = false, checkResponse: shouldCheckResponse = false } = opts;

  // Compute tool descriptor hash for rug-pull detection
  const hashInput = `${toolName}:${fn.toString()}`;
  const descriptorHash = createHash("sha256").update(hashInput).digest("hex");

  return async (...args: TArgs): Promise<TReturn> => {
    return withDelegation(opts.agentId ?? client.agentId, async () => {
      const params = args.length === 1 && typeof args[0] === "object" && args[0] !== null && !Array.isArray(args[0])
        ? (args[0] as Record<string, unknown>)
        : { args };

      const delegation = getDelegation();
      const proxyParams: Record<string, unknown> = { ...params };
      if (delegation && delegation.chain.length > 1) {
        proxyParams._delegation = {
          delegation_chain: delegation.chain,
          delegation_trace_id: delegation.traceId,
        };
      }

      let requestId = "";
      let scopeToken = "";
      try {
        const res = await client.proxy(toolName, proxyParams, targetUrl, undefined, descriptorHash);
        requestId = res.request_id;
        scopeToken = res.scope_token ?? "";
        if (!res.allowed) {
          // Gateway errors with failOpen: skip enforcement
          if (failOpen && (res as unknown as Record<string, unknown>)._gatewayError) {
            // fall through — allow execution
          } else {
            throw new ClampdBlockedError(res);
          }
        }
      } catch (e) {
        if (e instanceof ClampdBlockedError) throw e;
        if (!failOpen) throw new ClampdBlockedError({
          request_id: "error", allowed: false, risk_score: 1.0,
          denial_reason: String(e), latency_ms: 0, degraded_stages: [], session_flags: [],
        });
      }

      const result = await fn(...args);

      if (shouldCheckResponse) {
        await inspectResponse(client, toolName, result, requestId, failOpen, scopeToken);
      }

      return result;
    });
  };
}

// ── clampd.tools() — wrap OpenAI tool definitions ─────────────────

function tools(
  toolDefs: OpenAITool[],
  opts: WrapOptions,
): OpenAITool[] {
  const client = getClient({ agentId: opts.agentId });
  const { targetUrl = "", failOpen = false, scanInput = true, scanOutput = true } = opts;

  return toolDefs.map((tool) => {
    const original = tool.function.execute;
    if (typeof original !== "function") return tool;

    const wrapped = async (args: Record<string, unknown>): Promise<unknown> => {
      return withDelegation(opts.agentId ?? "", async () => {
        const delegation = getDelegation();
        const proxyParams: Record<string, unknown> = { ...args };
        if (delegation && delegation.chain.length > 1) {
          proxyParams._delegation = {
            delegation_chain: delegation.chain,
            delegation_trace_id: delegation.traceId,
          };
        }

        try {
          const res = await client.proxy(tool.function.name, proxyParams, targetUrl);
          if (!res.allowed) throw new ClampdBlockedError(res);
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
        }
        return original(args);
      });
    };

    return { ...tool, function: { ...tool.function, execute: wrapped } };
  });
}

// ── Minimal response shapes for type safety ──────────────────────

/** Minimal shape of an OpenAI chat completion response. */
interface OpenAIChatResponse {
  choices?: Array<{
    finish_reason?: string;
    message?: {
      content?: string | null;
      tool_calls?: Array<{
        function: { name: string; arguments: string | Record<string, unknown> };
      }>;
    };
  }>;
  [key: string]: unknown;
}

/** Minimal shape of an Anthropic message response. */
interface AnthropicMessageResponse {
  stop_reason?: string;
  content: Array<{
    type: string;
    text?: string;
    name?: string;
    input?: Record<string, unknown> | unknown;
  }>;
  [key: string]: unknown;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK wrapper must accept any client shape
type AnyFunction = (...args: any[]) => Promise<unknown>;

// ── clampd.openai() — wrap OpenAI client ──────────────────────────

function openai<T extends { chat: { completions: { create: AnyFunction } } }>(
  client: T,
  opts: WrapOptions,
): T {
  const clampdClient = getClient({ agentId: opts.agentId });
  const { targetUrl = "", failOpen = false, scanInput = true, scanOutput = true } = opts;
  const originalCreate = client.chat.completions.create.bind(client.chat.completions);

  // Extract tool names from OpenAI tool definitions for X-AG-Authorized-Tools header
  function extractToolNames(p: Record<string, unknown> | undefined): string[] | undefined {
    const tools = p?.tools as Array<Record<string, unknown>> | undefined;
    if (!tools?.length) return undefined;
    const names = tools
      .map((t) => (t.function as Record<string, unknown> | undefined)?.name as string | undefined)
      .filter((n): n is string => !!n);
    return names.length > 0 ? names : undefined;
  }

  (client.chat.completions as { create: AnyFunction }).create = async (...args: unknown[]): Promise<unknown> => {
    const params = args[0] as Record<string, unknown> | undefined;
    const _authorizedTools = extractToolNames(params);

    // ── STREAMING ──
    // Scan input, then wrap the stream to intercept tool calls as they complete.
    if (params?.stream) {
      // ── SCHEMA INJECTION PRE-SCAN ──
      if (params?.messages) {
        const schemaWarnings = scanForSchemaInjection(params.messages as Array<Record<string, unknown>>);
        if (schemaWarnings.length > 0 && schemaWarnings[0].riskScore >= 0.85) {
          throw new ClampdBlockedError({
            request_id: "schema-injection",
            allowed: false,
            risk_score: schemaWarnings[0].riskScore,
            denial_reason: `Schema injection detected: ${schemaWarnings[0].alertType} (pattern: ${schemaWarnings[0].matchedPattern})`,
            latency_ms: 0,
            degraded_stages: [],
            session_flags: [],
          });
        }
      }

      if (scanInput && params.messages) {
        const messages = params.messages as Array<Record<string, unknown>>;
        const userMessages = messages
          .filter((m) => m.role === "user" || m.role === "tool" || m.role === "function")
          .map((m) => typeof m.content === "string" ? m.content : JSON.stringify(m.content))
          .filter(Boolean)
          .join("\n");

        if (userMessages.trim()) {
          try {
            const inputResult = await clampdClient.scanInput(userMessages, messages.length);
            if (!inputResult.allowed) {
              throw new ClampdBlockedError({
                request_id: "scan-input",
                allowed: false,
                risk_score: inputResult.risk_score,
                denial_reason: inputResult.denial_reason || "Input blocked by guardrail",
                latency_ms: inputResult.latency_ms,
                degraded_stages: [],
                session_flags: [],
              });
            }
          } catch (e) {
            if (e instanceof ClampdBlockedError) throw e;
            if (!failOpen) throw e;
          }
        }
      }

      const stream = await originalCreate(...args);

      // Guard streaming tool calls only when guardStream is explicitly enabled.
      // When disabled, log a warning so developers know unguarded tool calls are flowing.
      const hasTools = (params?.tools as unknown[] | undefined)?.length;
      if (hasTools && stream && typeof (stream as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
        if (opts.guardStream) {
          return guardOpenAIStream(stream as AsyncIterable<unknown>, clampdClient, {
            agentId: opts.agentId ?? "",
            targetUrl,
            failOpen,
            authorizedTools: _authorizedTools,
          });
        } else {
          console.warn("[clampd] Streaming with tools detected but guardStream is not enabled. Tool calls in this stream are not guarded. Set { guardStream: true } to enable.");
        }
      }
      return stream;
    }

    // ── SCHEMA INJECTION PRE-SCAN ──
    if (params?.messages) {
      const schemaWarnings = scanForSchemaInjection(params.messages as Array<Record<string, unknown>>);
      if (schemaWarnings.length > 0 && schemaWarnings[0].riskScore >= 0.85) {
        throw new ClampdBlockedError({
          request_id: "schema-injection",
          allowed: false,
          risk_score: schemaWarnings[0].riskScore,
          denial_reason: `Schema injection detected: ${schemaWarnings[0].alertType} (pattern: ${schemaWarnings[0].matchedPattern})`,
          latency_ms: 0,
          degraded_stages: [],
          session_flags: [],
        });
      }
    }

    // ── INPUT GUARDRAIL ──
    if (scanInput && params?.messages) {
      const messages = params.messages as Array<Record<string, unknown>>;
      const userMessages = messages
        .filter((m) => m.role === "user" || m.role === "tool" || m.role === "function")
        .map((m) => typeof m.content === "string" ? m.content : JSON.stringify(m.content))
        .filter(Boolean)
        .join("\n");

      if (userMessages.trim()) {
        try {
          const inputResult = await clampdClient.scanInput(userMessages, messages.length);
          if (!inputResult.allowed) {
            throw new ClampdBlockedError({
              request_id: "scan-input",
              allowed: false,
              risk_score: inputResult.risk_score,
              denial_reason: inputResult.denial_reason || "Input blocked by guardrail",
              latency_ms: inputResult.latency_ms,
              degraded_stages: [],
              session_flags: [],
            });
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
          // fail-open: continue
        }
      }
    }

    const response = await originalCreate(...args) as OpenAIChatResponse;

    // ── OUTPUT GUARDRAIL ──
    if (scanOutput) {
      const content = response.choices?.[0]?.message?.content;
      if (content && content.length > 10) {
        try {
          const outputResult = await clampdClient.scanOutput(content);
          if (!outputResult.allowed) {
            throw new ClampdBlockedError({
              request_id: "scan-output",
              allowed: false,
              risk_score: outputResult.risk_score,
              denial_reason: outputResult.denial_reason || "Output blocked by guardrail",
              latency_ms: outputResult.latency_ms,
              degraded_stages: [],
              session_flags: [],
            });
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
        }
      }
    }

    const choice = response.choices?.[0];

    if (choice?.finish_reason !== "tool_calls" || !choice.message?.tool_calls?.length) {
      return response;
    }

    if (!choice.message.tool_calls || !Array.isArray(choice.message.tool_calls)) {
      return response;
    }

    for (const tc of choice.message.tool_calls) {
      // Schema registry hash verification
      if (opts.schemaRegistry && tc.function.name in opts.schemaRegistry) {
        const toolDef = (params?.tools as Array<Record<string, unknown>> | undefined)
          ?.find((t: Record<string, unknown>) => (t as { function?: { name?: string } }).function?.name === tc.function.name);
        if (toolDef) {
          const fn = (toolDef as { function: Record<string, unknown> }).function;
          const hashInput = `${fn.name ?? ""}|${fn.description ?? ""}|${JSON.stringify(fn.parameters ?? {}, Object.keys(fn.parameters ?? {}).sort())}`;
          const currentHash = createHash("sha256").update(hashInput).digest("hex");
          const expected = opts.schemaRegistry[tc.function.name].replace(/^sha256:/, "");
          if (currentHash !== expected) {
            throw new ClampdBlockedError({
              request_id: "descriptor-mismatch",
              allowed: false,
              risk_score: 0.95,
              denial_reason: `Tool descriptor hash mismatch for ${tc.function.name}: expected ${expected}, got ${currentHash}`,
              latency_ms: 0,
              degraded_stages: [],
              session_flags: [],
            });
          }
        }
      }

      let toolArgs: Record<string, unknown>;
      try {
        toolArgs = typeof tc.function.arguments === "string"
          ? JSON.parse(tc.function.arguments)
          : tc.function.arguments;
      } catch { toolArgs = { raw: tc.function.arguments }; }

      await withDelegation(opts.agentId ?? "", async () => {
        const delegation = getDelegation();
        const proxyParams: Record<string, unknown> = { ...toolArgs };
        if (delegation && delegation.chain.length > 1) {
          proxyParams._delegation = {
            delegation_chain: delegation.chain,
            delegation_trace_id: delegation.traceId,
          };
        }

        try {
          const res = await clampdClient.proxy(tc.function.name, proxyParams, targetUrl, undefined, undefined, _authorizedTools);
          if (!res.allowed) {
            throw new ClampdBlockedError(res);
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
        }
      });
    }

    return response;
  };

  return client;
}

// ── clampd.anthropic() — wrap Anthropic client ────────────────────

function anthropic<T extends { messages: { create: AnyFunction } }>(
  client: T,
  opts: WrapOptions,
): T {
  const clampdClient = getClient({ agentId: opts.agentId });
  const { targetUrl = "", failOpen = false, scanInput = true, scanOutput = true } = opts;
  const originalCreate = client.messages.create.bind(client.messages);

  // Extract tool names from Anthropic tool definitions
  function extractAnthropicToolNames(p: Record<string, unknown> | undefined): string[] | undefined {
    const tools = p?.tools as Array<Record<string, unknown>> | undefined;
    if (!tools?.length) return undefined;
    const names = tools
      .map((t) => t.name as string | undefined)
      .filter((n): n is string => !!n);
    return names.length > 0 ? names : undefined;
  }

  (client.messages as { create: AnyFunction }).create = async (...args: unknown[]): Promise<unknown> => {
    const params = args[0] as Record<string, unknown> | undefined;
    const _authorizedTools = extractAnthropicToolNames(params);

    // ── STREAMING ──
    // Scan input, then wrap the stream to intercept tool_use blocks as they complete.
    if (params?.stream) {
      // ── SCHEMA INJECTION PRE-SCAN ──
      if (params?.messages) {
        const schemaWarnings = scanForSchemaInjection(params.messages as Array<Record<string, unknown>>);
        if (schemaWarnings.length > 0 && schemaWarnings[0].riskScore >= 0.85) {
          throw new ClampdBlockedError({
            request_id: "schema-injection",
            allowed: false,
            risk_score: schemaWarnings[0].riskScore,
            denial_reason: `Schema injection detected: ${schemaWarnings[0].alertType} (pattern: ${schemaWarnings[0].matchedPattern})`,
            latency_ms: 0,
            degraded_stages: [],
            session_flags: [],
          });
        }
      }

      if (scanInput && params.messages) {
        const messages = params.messages as Array<Record<string, unknown>>;
        const userMessages = messages
          .filter((m) => m.role === "user" || m.role === "tool" || m.role === "function")
          .map((m) => {
            if (typeof m.content === "string") return m.content;
            if (Array.isArray(m.content)) {
              return (m.content as Array<Record<string, unknown>>)
                .filter((b) => b.type === "text")
                .map((b) => b.text)
                .join("\n");
            }
            return JSON.stringify(m.content);
          })
          .filter(Boolean)
          .join("\n");

        if (userMessages.trim()) {
          try {
            const inputResult = await clampdClient.scanInput(userMessages, messages.length);
            if (!inputResult.allowed) {
              throw new ClampdBlockedError({
                request_id: "scan-input",
                allowed: false,
                risk_score: inputResult.risk_score,
                denial_reason: inputResult.denial_reason || "Input blocked by guardrail",
                latency_ms: inputResult.latency_ms,
                degraded_stages: [],
                session_flags: [],
              });
            }
          } catch (e) {
            if (e instanceof ClampdBlockedError) throw e;
            if (!failOpen) throw e;
          }
        }
      }

      const stream = await originalCreate(...args);

      // Guard streaming tool calls only when guardStream is explicitly enabled.
      const hasTools = (params?.tools as unknown[] | undefined)?.length;
      if (hasTools && stream && typeof (stream as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
        if (opts.guardStream) {
          return guardAnthropicStream(stream as AsyncIterable<unknown>, clampdClient, {
            agentId: opts.agentId ?? "",
            targetUrl,
            failOpen,
            authorizedTools: _authorizedTools,
          });
        } else {
          console.warn("[clampd] Streaming with tools detected but guardStream is not enabled. Tool calls in this stream are not guarded. Set { guardStream: true } to enable.");
        }
      }
      return stream;
    }

    // ── SCHEMA INJECTION PRE-SCAN ──
    if (params?.messages) {
      const schemaWarnings = scanForSchemaInjection(params.messages as Array<Record<string, unknown>>);
      if (schemaWarnings.length > 0 && schemaWarnings[0].riskScore >= 0.85) {
        throw new ClampdBlockedError({
          request_id: "schema-injection",
          allowed: false,
          risk_score: schemaWarnings[0].riskScore,
          denial_reason: `Schema injection detected: ${schemaWarnings[0].alertType} (pattern: ${schemaWarnings[0].matchedPattern})`,
          latency_ms: 0,
          degraded_stages: [],
          session_flags: [],
        });
      }
    }

    // ── INPUT GUARDRAIL ──
    if (scanInput && params?.messages) {
      const messages = params.messages as Array<Record<string, unknown>>;
      const userMessages = messages
        .filter((m) => m.role === "user" || m.role === "tool" || m.role === "function")
        .map((m) => {
          if (typeof m.content === "string") return m.content;
          if (Array.isArray(m.content)) {
            return (m.content as Array<Record<string, unknown>>)
              .filter((b) => b.type === "text")
              .map((b) => b.text)
              .join("\n");
          }
          return JSON.stringify(m.content);
        })
        .filter(Boolean)
        .join("\n");

      if (userMessages.trim()) {
        try {
          const inputResult = await clampdClient.scanInput(userMessages, messages.length);
          if (!inputResult.allowed) {
            throw new ClampdBlockedError({
              request_id: "scan-input",
              allowed: false,
              risk_score: inputResult.risk_score,
              denial_reason: inputResult.denial_reason || "Input blocked by guardrail",
              latency_ms: inputResult.latency_ms,
              degraded_stages: [],
              session_flags: [],
            });
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
        }
      }
    }

    const response = await originalCreate(...args) as AnthropicMessageResponse;

    // ── OUTPUT GUARDRAIL ──
    if (scanOutput) {
      const contentArr = Array.isArray(response.content) ? response.content : [];
      const textContent = contentArr
        .filter((b) => b.type === "text" && b.text)
        .map((b) => b.text!)
        .join("\n");

      if (textContent.length > 10) {
        try {
          const outputResult = await clampdClient.scanOutput(textContent);
          if (!outputResult.allowed) {
            throw new ClampdBlockedError({
              request_id: "scan-output",
              allowed: false,
              risk_score: outputResult.risk_score,
              denial_reason: outputResult.denial_reason || "Output blocked by guardrail",
              latency_ms: outputResult.latency_ms,
              degraded_stages: [],
              session_flags: [],
            });
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
        }
      }
    }

    if (response.stop_reason !== "tool_use") return response;

    if (!response.content || !Array.isArray(response.content)) {
      return response as unknown;
    }

    for (const block of response.content) {
      if (block.type !== "tool_use") continue;
      const toolArgs = typeof block.input === "object" ? block.input : {};

      await withDelegation(opts.agentId ?? "", async () => {
        const delegation = getDelegation();
        const proxyParams: Record<string, unknown> = { ...(toolArgs as Record<string, unknown>) };
        if (delegation && delegation.chain.length > 1) {
          proxyParams._delegation = {
            delegation_chain: delegation.chain,
            delegation_trace_id: delegation.traceId,
          };
        }

        try {
          const res = await clampdClient.proxy(block.name ?? "unknown", proxyParams, targetUrl, undefined, undefined, _authorizedTools);
          if (!res.allowed) {
            throw new ClampdBlockedError(res);
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw e;
        }
      });
    }

    return response;
  };

  return client;
}

// ── clampd.adk() — Google ADK callbacks ─────────────────────────

interface AdkOptions {
  agentId?: string;
  targetUrl?: string;
  failOpen?: boolean;
  checkResponse?: boolean;
  secret?: string;
}

interface AdkCallbacks {
  beforeTool: (toolName: string, args: Record<string, unknown>) => Promise<null | { error: string }>;
  afterTool?: (toolName: string, response: unknown) => Promise<null | { error: string }>;
}

function adk(opts: AdkOptions): AdkCallbacks {
  const client = getClient({ agentId: opts.agentId, secret: opts.secret });
  const { targetUrl = "", failOpen = false, checkResponse = false } = opts;

  const beforeTool = async (toolName: string, args: Record<string, unknown>): Promise<null | { error: string }> => {
    return withDelegation(opts.agentId ?? client.agentId, async () => {
      const delegation = getDelegation();
      const proxyParams: Record<string, unknown> = { ...args };
      if (delegation && delegation.chain.length > 1) {
        proxyParams._delegation = {
          delegation_chain: delegation.chain,
          delegation_trace_id: delegation.traceId,
        };
      }

      try {
        const res = await client.proxy(toolName, proxyParams, targetUrl);
        if (!res.allowed) {
          if (failOpen && (res as unknown as Record<string, unknown>)._gatewayError) return null;
          return { error: res.denial_reason || "Blocked by Clampd gateway" };
        }
      } catch (e) {
        if (e instanceof ClampdBlockedError) {
          return { error: (e as ClampdBlockedError).response.denial_reason || "Blocked by Clampd gateway" };
        }
        if (!failOpen) {
          return { error: `Clampd gateway error: ${e}` };
        }
      }

      return null;
    });
  };

  const result: AdkCallbacks = { beforeTool };

  if (checkResponse) {
    result.afterTool = async (toolName: string, response: unknown): Promise<null | { error: string }> => {
      return withDelegation(opts.agentId ?? client.agentId, async () => {
        try {
          const res = await client.inspect(toolName, response);
          if (!res.allowed) {
            return { error: res.denial_reason || "Response blocked by Clampd gateway" };
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) {
            return { error: (e as ClampdBlockedError).response.denial_reason || "Response blocked by Clampd gateway" };
          }
          if (!failOpen) {
            return { error: `Clampd response inspection error: ${e}` };
          }
        }

        return null;
      });
    };
  }

  return result;
}

// ── clampd.vercelAI() — wrap Vercel AI SDK tools ────────────────

interface VercelAITool {
  description?: string;
  parameters?: unknown;
  execute?: (args: Record<string, unknown>) => Promise<unknown>;
  [key: string]: unknown;
}

function vercelAI<T extends Record<string, VercelAITool>>(
  toolDefs: T,
  opts: WrapOptions,
): T {
  const client = getClient({ agentId: opts.agentId });
  const { targetUrl = "", failOpen = false, checkResponse: shouldCheckResponse = false } = opts;

  const wrapped = {} as Record<string, VercelAITool>;

  for (const [toolName, tool] of Object.entries(toolDefs)) {
    if (typeof tool.execute !== "function") {
      wrapped[toolName] = tool;
      continue;
    }

    const originalExecute = tool.execute;

    const wrappedExecute = async (args: Record<string, unknown>): Promise<unknown> => {
      return withDelegation(opts.agentId ?? "", async () => {
        const delegation = getDelegation();
        const proxyParams: Record<string, unknown> = { ...args };
        if (delegation && delegation.chain.length > 1) {
          proxyParams._delegation = {
            delegation_chain: delegation.chain,
            delegation_trace_id: delegation.traceId,
          };
        }

        let requestId = "";
        let scopeToken = "";
        try {
          const res = await client.proxy(toolName, proxyParams, targetUrl);
          requestId = res.request_id;
          scopeToken = res.scope_token ?? "";
          if (!res.allowed) {
            throw new ClampdBlockedError(res);
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) throw e;
          if (!failOpen) throw new ClampdBlockedError({
            request_id: "error", allowed: false, risk_score: 1.0,
            denial_reason: String(e), latency_ms: 0, degraded_stages: [], session_flags: [],
          });
        }

        const result = await originalExecute(args);

        if (shouldCheckResponse) {
          await inspectResponse(client, toolName, result, requestId, failOpen, scopeToken);
        }

        return result;
      });
    };

    wrapped[toolName] = { ...tool, execute: wrappedExecute };
  }

  return wrapped as T;
}

// ── clampd.agent() — auto-delegation scope ──────────────────────

/**
 * Run a function within an agent's delegation scope.
 *
 * Instead of manually using `withDelegation()`, wrap your agent logic
 * with `clampd.agent()` — all `guard()` calls inside automatically
 * inherit the delegation chain.
 *
 * @example
 * ```ts
 * // Before (manual):
 * return withDelegation("orchestrator", async () => { ... });
 *
 * // After (automatic):
 * return clampd.agent("orchestrator", async () => { ... });
 * ```
 */
function agent<T>(agentId: string, fn: () => Promise<T>): Promise<T> {
  return withDelegation(agentId, fn);
}

// ── Default export ────────────────────────────────────────────────

export type { AdkOptions, AdkCallbacks, VercelAITool };

const clampd = { init, guard, tools, openai, anthropic, adk, vercelAI, agent, delegationHeaders, scanForSchemaInjection };
export default clampd;
