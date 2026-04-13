/**
 * Clampd SDK shared guardrail helpers.
 *
 * Contains response inspection logic and helper functions for schema injection
 * pre-scanning and tool name extraction, used across openai/anthropic/guard wrappers.
 *
 * Extracted from index.ts to reduce duplication.
 */

import { ClampdClient, type ScanResponse } from "./client.js";
import { ClampdBlockedError } from "./interceptor.js";
import { scanForSchemaInjection } from "./schema-injection.js";
import { withDelegation, getDelegation } from "./delegation.js";
import { setScopeToken, withScopeToken } from "./tool-verify.js";

// Re-export scanForSchemaInjection so callers that import from guardrails.js get it
export { scanForSchemaInjection } from "./schema-injection.js";

// ── Response inspection helper ────────────────────────────────────

/**
 * Inspect a tool response for anomalies, scope violations, and sensitive data.
 *
 * Calls `client.inspect()` which forwards to the gateway's `/v1/inspect` endpoint.
 * PII/secrets detection is handled server-side by the gateway — no separate
 * `scanOutput()` call needed for tool responses.
 *
 * Throws `ClampdBlockedError` if the check fails (unless `failOpen` is true,
 * in which case gateway/network errors are swallowed).
 */
export async function inspectResponse(
  client: ClampdClient,
  tool: string,
  responseData: unknown,
  requestId: string = "",
  failOpen: boolean = false,
  scopeToken: string = "",
): Promise<void> {
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
}

// ── Schema injection pre-scan ────────────────────────────────────

/**
 * Scan messages for schema injection attempts and throw if the highest-risk
 * warning has a risk score >= 0.85.
 *
 * This wraps the repeated pattern found in both the OpenAI and Anthropic
 * wrappers so callers can replace ~10 lines with a single call.
 *
 * @throws {ClampdBlockedError} when a high-confidence schema injection is detected.
 */
export function schemaInjectionPreScan(messages: Array<Record<string, unknown>>): void {
  const schemaWarnings = scanForSchemaInjection(messages);
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

// ── Tool name extraction helpers ─────────────────────────────────

/**
 * Extract tool names from OpenAI-style tool definitions.
 *
 * OpenAI tools have the shape `{ type: "function", function: { name: "..." } }`.
 * Returns `undefined` when no tool names can be extracted (no tools or empty array).
 */
export function extractOpenAIToolNames(params: Record<string, unknown> | undefined): string[] | undefined {
  const tools = params?.tools as Array<Record<string, unknown>> | undefined;
  if (!tools?.length) return undefined;
  const names = tools
    .map((t) => (t.function as Record<string, unknown> | undefined)?.name as string | undefined)
    .filter((n): n is string => !!n);
  return names.length > 0 ? names : undefined;
}

/**
 * Extract tool names from Anthropic-style tool definitions.
 *
 * Anthropic tools have the shape `{ name: "...", input_schema: { ... } }`.
 * Returns `undefined` when no tool names can be extracted (no tools or empty array).
 */
export function extractAnthropicToolNames(params: Record<string, unknown> | undefined): string[] | undefined {
  const tools = params?.tools as Array<Record<string, unknown>> | undefined;
  if (!tools?.length) return undefined;
  const names = tools
    .map((t) => t.name as string | undefined)
    .filter((n): n is string => !!n);
  return names.length > 0 ? names : undefined;
}

// ── Input scanning helpers ──────────────────────────────────────

/**
 * Extract user/tool/function messages from OpenAI format and scan for prompt injection.
 */
export async function scanInputOpenAI(
  client: ClampdClient,
  messages: Array<Record<string, unknown>>,
  failOpen: boolean,
): Promise<void> {
  const userMessages = messages
    .filter((m) => m.role === "user" || m.role === "tool" || m.role === "function")
    .map((m) => typeof m.content === "string" ? m.content : JSON.stringify(m.content))
    .filter(Boolean)
    .join("\n");

  if (!userMessages.trim()) return;

  try {
    const inputResult = await client.scanInput(userMessages, messages.length);
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

/**
 * Extract user/tool messages from Anthropic format and scan for prompt injection.
 * Handles both string and array (content blocks) format.
 */
export async function scanInputAnthropic(
  client: ClampdClient,
  messages: Array<Record<string, unknown>>,
  failOpen: boolean,
): Promise<void> {
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

  if (!userMessages.trim()) return;

  try {
    const inputResult = await client.scanInput(userMessages, messages.length);
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

// ── Output scanning helper ──────────────────────────────────────

/**
 * Scan output content for PII/secrets. Skips trivial responses (<=10 chars).
 */
export async function scanOutputContent(
  client: ClampdClient,
  content: string,
  failOpen: boolean,
): Promise<void> {
  if (!content) return;
  try {
    const outputResult = await client.scanOutput(content);
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

// ── Tool call guarding helper ───────────────────────────────────

/**
 * Guard a single tool call through the proxy with delegation context.
 */
export async function guardToolCallWithDelegation(
  client: ClampdClient,
  agentId: string,
  toolName: string,
  toolArgs: Record<string, unknown>,
  targetUrl: string,
  failOpen: boolean,
  authorizedTools?: string[],
): Promise<void> {
  await withDelegation(agentId, async () => {
    const delegation = getDelegation();
    const proxyParams: Record<string, unknown> = { ...toolArgs };
    if (delegation && delegation.chain.length > 1) {
      proxyParams._delegation = {
        delegation_chain: delegation.chain,
        delegation_trace_id: delegation.traceId,
      };
    }

    try {
      const res = await client.proxy(toolName, proxyParams, targetUrl, undefined, undefined, authorizedTools);
      if (res.allowed && res.scope_token) {
        setScopeToken(res.scope_token);
      }
      if (!res.allowed) {
        throw new ClampdBlockedError(res);
      }
    } catch (e) {
      if (e instanceof ClampdBlockedError) throw e;
      if (!failOpen) throw e;
    }
  });
}
