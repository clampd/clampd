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
import { ClampdBlockedError, type OpenAITool } from "./interceptor.js";
import { withDelegation, getDelegation, delegationHeaders } from "./delegation.js";
import { scanForSchemaInjection } from "./schema-injection.js";
import { guardOpenAIStream, guardAnthropicStream } from "./stream-guard.js";
import { setScopeToken, withScopeToken } from "./tool-verify.js";
import { getClient, init, _reset, sortedStringify, type GuardOptions, type WrapOptions } from "./config.js";
import { inspectResponse, schemaInjectionPreScan, extractOpenAIToolNames, extractAnthropicToolNames, scanInputOpenAI, scanInputAnthropic, scanOutputContent, guardToolCallWithDelegation } from "./guardrails.js";

// ── Public API ──────────────────────────────────────────────────────
export { ClampdBlockedError, type OpenAITool } from "./interceptor.js";
export { delegationHeaders } from "./delegation.js";
export { scanForSchemaInjection, type SchemaInjectionWarning } from "./schema-injection.js";
export { verifyScopeToken, requireScope, getCurrentScopeToken, ScopeVerificationError } from "./tool-verify.js";
export type { ScopeTokenClaims } from "./tool-verify.js";

// ── Advanced / escape-hatch exports ─────────────────────────────────
// Exposed for custom gateway setups or multi-service architectures.
// Most users should use the default export (clampd.openai(), clampd.guard(), etc.).
export { ClampdClient, type ClampdClientOptions } from "./client.js";
export { makeAgentJwt } from "./auth.js";
export type { ProxyResponse, ScanResponse, ScanOutputResponse } from "./client.js";

/** Recursively freeze an object and all nested objects/arrays. */
function deepFreeze(obj: Record<string, unknown>): void {
  Object.freeze(obj);
  for (const val of Object.values(obj)) {
    if (val !== null && typeof val === "object" && !Object.isFrozen(val)) {
      deepFreeze(val as Record<string, unknown>);
    }
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
          if (failOpen && res._gatewayError) {
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

      // Deep freeze params to prevent mutation between guard approval and execution (TOCTOU)
      if (args.length === 1 && typeof args[0] === "object" && args[0] !== null) {
        deepFreeze(args[0] as Record<string, unknown>);
      }

      // Run the function inside withScopeToken so downstream
      // requireScope()/getCurrentScopeToken() reads from async context
      const executeAndInspect = async () => {
        const result = await fn(...args);
        if (shouldCheckResponse) {
          await inspectResponse(client, toolName, result, requestId, failOpen, scopeToken);
        }
        return result;
      };

      if (scopeToken) {
        setScopeToken(scopeToken); // fallback for non-async contexts
        return withScopeToken(scopeToken, executeAndInspect);
      }
      return executeAndInspect();
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

        let scopeToken = "";
        try {
          const res = await client.proxy(tool.function.name, proxyParams, targetUrl);
          scopeToken = res.scope_token ?? "";
          if (!res.allowed) {
            if (failOpen && res._gatewayError) {
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

        // Freeze args to prevent mutation between guard approval and execution (TOCTOU)
        deepFreeze(args);

        if (scopeToken) {
          setScopeToken(scopeToken);
          return withScopeToken(scopeToken, () => original(args));
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

  const guardedCreate = async (...args: unknown[]): Promise<unknown> => {
    const params = args[0] as Record<string, unknown> | undefined;
    const _authorizedTools = extractOpenAIToolNames(params);

    // ── STREAMING ──
    // Scan input, then wrap the stream to intercept tool calls as they complete.
    if (params?.stream) {
      // ── SCHEMA INJECTION PRE-SCAN ──
      if (params?.messages) {
        schemaInjectionPreScan(params.messages as Array<Record<string, unknown>>);
      }

      if (scanInput && params.messages) {
        await scanInputOpenAI(clampdClient, params.messages as Array<Record<string, unknown>>, failOpen);
      }

      const stream = await originalCreate(...args);

      // Guard streaming tool calls only when guardStream is explicitly enabled.
      // When disabled, log a warning so developers know unguarded tool calls are flowing.
      const hasTools = (params?.tools as unknown[] | undefined)?.length;
      if (hasTools && stream && typeof (stream as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
        if (opts.guardStream !== false) {
          return guardOpenAIStream(stream as AsyncIterable<unknown>, clampdClient, {
            agentId: opts.agentId ?? "",
            targetUrl,
            failOpen,
            authorizedTools: _authorizedTools,
          });
        } else {
          console.warn("[clampd] guardStream explicitly disabled — streaming tool calls are not guarded.");
        }
      }
      return stream;
    }

    // ── SCHEMA INJECTION PRE-SCAN ──
    if (params?.messages) {
      schemaInjectionPreScan(params.messages as Array<Record<string, unknown>>);
    }

    // ── INPUT GUARDRAIL ──
    if (scanInput && params?.messages) {
      await scanInputOpenAI(clampdClient, params.messages as Array<Record<string, unknown>>, failOpen);
    }

    const response = await originalCreate(...args) as OpenAIChatResponse;

    // ── OUTPUT GUARDRAIL ──
    if (scanOutput) {
      const content = response.choices?.[0]?.message?.content;
      if (content) await scanOutputContent(clampdClient, content, failOpen);
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
          const hashInput = `${fn.name ?? ""}|${fn.description ?? ""}|${sortedStringify(fn.parameters ?? {})}`;
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

      await guardToolCallWithDelegation(clampdClient, opts.agentId ?? "", tc.function.name, toolArgs, targetUrl, failOpen, _authorizedTools);
    }

    return response;
  };

  // Return a Proxy instead of mutating the original client (#8)
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "chat") {
        return new Proxy(target.chat, {
          get(chatTarget, chatProp, chatReceiver) {
            if (chatProp === "completions") {
              return new Proxy(chatTarget.completions, {
                get(compTarget, compProp, compReceiver) {
                  if (compProp === "create") return guardedCreate;
                  return Reflect.get(compTarget, compProp, compReceiver);
                },
              });
            }
            return Reflect.get(chatTarget, chatProp, chatReceiver);
          },
        });
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

// ── clampd.anthropic() — wrap Anthropic client ────────────────────

function anthropic<T extends { messages: { create: AnyFunction } }>(
  client: T,
  opts: WrapOptions,
): T {
  const clampdClient = getClient({ agentId: opts.agentId });
  const { targetUrl = "", failOpen = false, scanInput = true, scanOutput = true } = opts;
  const originalCreate = client.messages.create.bind(client.messages);

  const guardedCreate = async (...args: unknown[]): Promise<unknown> => {
    const params = args[0] as Record<string, unknown> | undefined;
    const _authorizedTools = extractAnthropicToolNames(params);

    // ── STREAMING ──
    // Scan input, then wrap the stream to intercept tool_use blocks as they complete.
    if (params?.stream) {
      // ── SCHEMA INJECTION PRE-SCAN ──
      if (params?.messages) {
        schemaInjectionPreScan(params.messages as Array<Record<string, unknown>>);
      }

      if (scanInput && params.messages) {
        await scanInputAnthropic(clampdClient, params.messages as Array<Record<string, unknown>>, failOpen);
      }

      const stream = await originalCreate(...args);

      // Guard streaming tool calls only when guardStream is explicitly enabled.
      const hasTools = (params?.tools as unknown[] | undefined)?.length;
      if (hasTools && stream && typeof (stream as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
        if (opts.guardStream !== false) {
          return guardAnthropicStream(stream as AsyncIterable<unknown>, clampdClient, {
            agentId: opts.agentId ?? "",
            targetUrl,
            failOpen,
            authorizedTools: _authorizedTools,
          });
        } else {
          console.warn("[clampd] guardStream explicitly disabled — streaming tool calls are not guarded.");
        }
      }
      return stream;
    }

    // ── SCHEMA INJECTION PRE-SCAN ──
    if (params?.messages) {
      schemaInjectionPreScan(params.messages as Array<Record<string, unknown>>);
    }

    // ── INPUT GUARDRAIL ──
    if (scanInput && params?.messages) {
      await scanInputAnthropic(clampdClient, params.messages as Array<Record<string, unknown>>, failOpen);
    }

    const response = await originalCreate(...args) as AnthropicMessageResponse;

    // ── OUTPUT GUARDRAIL ──
    if (scanOutput) {
      const contentArr = Array.isArray(response.content) ? response.content : [];
      const textContent = contentArr
        .filter((b) => b.type === "text" && b.text)
        .map((b) => b.text!)
        .join("\n");

      if (textContent) await scanOutputContent(clampdClient, textContent, failOpen);
    }

    if (response.stop_reason !== "tool_use") return response;

    if (!response.content || !Array.isArray(response.content)) {
      return response as unknown;
    }

    for (const block of response.content) {
      if (block.type !== "tool_use") continue;
      const toolArgs = typeof block.input === "object" ? block.input : {};

      await guardToolCallWithDelegation(clampdClient, opts.agentId ?? "", block.name ?? "unknown", toolArgs as Record<string, unknown>, targetUrl, failOpen, _authorizedTools);
    }

    return response;
  };

  // Return a Proxy instead of mutating the original client (#8)
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "messages") {
        return new Proxy(target.messages, {
          get(msgTarget, msgProp, msgReceiver) {
            if (msgProp === "create") return guardedCreate;
            return Reflect.get(msgTarget, msgProp, msgReceiver);
          },
        });
      }
      return Reflect.get(target, prop, receiver);
    },
  });
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

  // Track last scope token for passing to afterTool inspect call
  let _lastScopeToken = "";

  const beforeTool = async (toolName: string, args: Record<string, unknown>): Promise<null | { error: string }> => {
    _lastScopeToken = "";
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
        if (res.allowed && res.scope_token) {
          setScopeToken(res.scope_token);
          _lastScopeToken = res.scope_token;
        }
        if (!res.allowed) {
          if (failOpen && res._gatewayError) return null;
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
          const res = await client.inspect(toolName, response, undefined, _lastScopeToken || undefined);
          if (!res.allowed) {
            return { error: res.denial_reason || "Response blocked by Clampd gateway" };
          }
        } catch (e) {
          if (e instanceof ClampdBlockedError) {
            return { error: e.response.denial_reason || "Response blocked by Clampd gateway" };
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

        // Freeze args to prevent mutation between guard approval and execution (TOCTOU)
        deepFreeze(args);

        const executeAndInspect = async () => {
          const result = await originalExecute(args);
          if (shouldCheckResponse) {
            await inspectResponse(client, toolName, result, requestId, failOpen, scopeToken);
          }
          return result;
        };

        if (scopeToken) {
          setScopeToken(scopeToken);
          return withScopeToken(scopeToken, executeAndInspect);
        }
        return executeAndInspect();
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

const clampd = { init, guard, tools, openai, anthropic, adk, vercelAI, agent, delegationHeaders, scanForSchemaInjection, _reset };
export default clampd;
