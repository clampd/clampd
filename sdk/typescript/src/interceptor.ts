/**
 * Generic interceptor for Clampd — wraps ANY tool or function call
 * through the Clampd security proxy pipeline.
 *
 * Three interception patterns:
 *
 *   A. `wrapFunction`    — wrap any async function
 *   B. `wrapOpenAITools`  — wrap OpenAI / Vercel AI SDK tool definitions
 *   C. `ClampdGuard`     — middleware for any framework (check + execute)
 *
 * No external dependencies — pure TypeScript.
 */

import { ClampdClient, type ProxyResponse } from "./client.js";
import { contractHash } from "./contract-hash.js";
import { setScopeToken, withScopeToken } from "./tool-verify.js";
import { raiseIfUnregistered } from "./_frameworkAdapters.js";
import {
  renderCorrectiveForLLM,
  type StructuredDenial,
} from "./corrective.js";

// ── Types ─────────────────────────────────────────────────────────

/**
 * OpenAI-compatible tool definition.
 *
 * Matches the shape used by the OpenAI Node SDK, Vercel AI SDK, and
 * most LLM tool-calling libraries:
 *
 * ```ts
 * {
 *   type: "function",
 *   function: {
 *     name: "get_weather",
 *     description: "Looks up current weather for a city",
 *     parameters: { ... },       // JSON Schema
 *     execute: async (args) => { ... },
 *   },
 * }
 * ```
 *
 * The `execute` field is optional in the OpenAI spec but required for
 * interception — if a tool has no `execute` it is passed through as-is.
 */
export interface OpenAIToolFunction {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  execute?: (args: Record<string, unknown>) => Promise<unknown>;
  [key: string]: unknown; // allow additional vendor fields
}

export interface OpenAITool {
  type: "function";
  function: OpenAIToolFunction;
  [key: string]: unknown; // allow additional vendor fields
}

// ── Error ─────────────────────────────────────────────────────────

/**
 * Thrown when the Clampd proxy denies a tool call and `blockOnDeny`
 * is enabled (the default).
 *
 * v0.20: carries the typed `StructuredDenial` from the gateway, including
 * a structured `CorrectiveAction` the LLM tool loop can pattern-match on.
 * Call `.toToolResult()` to get a rendered string suitable for
 * `tool_result.content` in OpenAI / Anthropic tool-use turns.
 */
export class ClampdBlockedError extends Error {
  public readonly response: ProxyResponse;
  public readonly matchedRules: string[];
  public readonly sessionFlags: string[];
  /** The typed denial returned by the gateway. Always set; built from
   * the response's `denial` field (or `unknown reason` fallback). */
  public readonly denial: StructuredDenial;

  constructor(response: ProxyResponse) {
    const denial: StructuredDenial = response.denial ?? {
      // Defensive fallback when the response has no typed denial
      // (synthetic SDK errors built with legacy `denial_reason: "..."` kwarg
      // or hypothetical pre-v0.20 gateway). We synthesize a typed shape
      // from whatever the response carries so callers can rely on
      // `.denial` always being populated.
      ruleId: "SDK/synthetic",
      violatedPredicate: response.denial_reason ?? "unknown reason",
      offendingValue: "",
      corrective: null,
      reasonCodes: [],
      boundaryViolation: null,
      boundaryMatchedRule: null,
      idempotencyKey: null,
    };
    const reason =
      denial.corrective?.humanExplanation ??
      denial.violatedPredicate ??
      "unknown reason";
    const parts = [`Blocked: ${reason} (risk=${response.risk_score.toFixed(2)})`];
    if (response.matched_rules?.length) {
      parts.push(`rules: ${response.matched_rules.join(", ")}`);
    }
    if (response.session_flags?.length) {
      parts.push(`session: ${response.session_flags.join(", ")}`);
    }
    super(parts.join(" | "));
    this.name = "ClampdBlockedError";
    this.response = response;
    this.denial = denial;
    this.matchedRules = response.matched_rules ?? [];
    this.sessionFlags = response.session_flags ?? [];
  }

  /**
   * Render the corrective for an LLM `tool_result.content` turn.
   * Returns the rendered hint when present and confidence is not "low";
   * falls back to the violated predicate so the LLM still sees a reason.
   */
  /**
   * Subtype check: was this denial flagged as an LLM loop by the SDK?
   * Identical to `instanceof ClampdLoopError` but more readable in
   * narrowing.
   */
  isLoop(): this is ClampdLoopError {
    return this instanceof ClampdLoopError;
  }

  toToolResult(): string {
    return (
      renderCorrectiveForLLM(this.denial.corrective) ||
      `Denied: ${this.denial.violatedPredicate || "policy violation"}`
    );
  }
}

/**
 * Helper: throw the right denial class based on whether the client's
 * loop-detection ring has already seen this response's idempotency key.
 *
 * Use this in wrappers in place of `throw new ClampdBlockedError(resp)`
 * so loop escalation is consistent across all surfaces. Synthetic
 * responses (no idempotency key) always fall through to the regular
 * `ClampdBlockedError`.
 */
export function throwBlockedOrLoop(
  client: ClampdClient,
  response: ProxyResponse,
): never {
  if (client.recordAndCheckLoop(response)) {
    throw new ClampdLoopError(response);
  }
  throw new ClampdBlockedError(response);
}

/**
 * Raised when the LLM is detected to be looping on the same denial.
 *
 * The gateway emits a stable `idempotency_key` for each (agent, tool,
 * params, rule, corrective) tuple. The SDK tracks the most recent keys
 * per-client. If a denial arrives with a key already seen, the LLM has
 * retried the exact same call after being told to stop.
 *
 * Subclasses `ClampdBlockedError` so existing `catch (ClampdBlockedError)`
 * chains propagate it correctly. Callers wanting to treat loops as
 * terminal should `catch (e) { if (e instanceof ClampdLoopError) ... }`
 * BEFORE the generic block handler.
 */
export class ClampdLoopError extends ClampdBlockedError {
  constructor(response: ProxyResponse) {
    super(response);
    this.name = "ClampdLoopError";
    const id = this.denial.idempotencyKey ?? "<no-id>";
    this.message =
      `LLM loop detected on ${this.denial.ruleId || "unknown"}: same denial ` +
      `received again (idempotency key ${id}). Stop retrying identical inputs.`;
  }
}

// ── Pattern A: wrapFunction ───────────────────────────────────────

export interface WrapFunctionOptions<TArgs extends unknown[]> {
  /** ClampdClient instance for proxy calls. */
  client: ClampdClient;

  /** Tool name sent to the Clampd pipeline (e.g. "http.fetch"). */
  toolName: string;

  /**
   * Upstream tool URL. If omitted the proxy call uses an empty string
   * which tells the gateway to skip forwarding (verify-only mode).
   */
  targetUrl?: string;

  /**
   * Converts the original function arguments into a flat params dict
   * for the Clampd proxy request.
   *
   * If not provided the interceptor applies a default strategy:
   *   - 0 args  => `{}`
   *   - 1 arg that is a plain object => pass it through
   *   - otherwise => `{ args: [...] }`
   */
  paramExtractor?: (...args: TArgs) => Record<string, unknown>;

  /**
   * When `true` (default), a denied proxy response throws
   * `ClampdBlockedError` instead of executing the wrapped function.
   */
  blockOnDeny?: boolean;

  /** Optional prompt context forwarded to the gateway. */
  promptContext?: string;

  /** Tool description — used to compute descriptor_hash for rug-pull detection. */
  description?: string;
  /** JSON Schema of tool parameters — used to compute descriptor_hash. */
  paramSchema?: Record<string, unknown>;
}

/**
 * Extract params from arbitrary function arguments using the default
 * heuristic when no `paramExtractor` is supplied.
 */
function defaultExtractParams(args: unknown[]): Record<string, unknown> {
  if (args.length === 0) {
    return {};
  }

  if (args.length === 1) {
    const single = args[0];
    if (
      single !== null &&
      typeof single === "object" &&
      !Array.isArray(single)
    ) {
      return single as Record<string, unknown>;
    }
    return { arg: single };
  }

  return { args };
}

/**
 * Wrap any async function so every invocation first passes through the
 * Clampd security pipeline.
 *
 * ```ts
 * const guardedFetch = wrapFunction(myFetchFn, {
 *   client,
 *   toolName: "http.fetch",
 *   targetUrl: "http://tool:5555",
 *   paramExtractor: (url, opts) => ({ url, method: opts?.method ?? "GET" }),
 * });
 * const result = await guardedFetch("https://api.example.com", { method: "GET" });
 * ```
 */
export function wrapFunction<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => Promise<TReturn>,
  opts: WrapFunctionOptions<TArgs>,
): (...args: TArgs) => Promise<TReturn> {
  const {
    client,
    toolName,
    targetUrl = "",
    paramExtractor,
    blockOnDeny = true,
    promptContext,
    description,
    paramSchema,
  } = opts;

  const descriptorHash =
    description !== undefined || paramSchema !== undefined
      ? contractHash({
          name: toolName,
          description: description ?? "",
          parameters: (paramSchema as object) ?? {},
        })
      : undefined;

  return async (...args: TArgs): Promise<TReturn> => {
    const params = paramExtractor
      ? paramExtractor(...args)
      : defaultExtractParams(args as unknown[]);

    const proxyRes = await client.proxy(
      toolName,
      params,
      targetUrl,
      promptContext,
      descriptorHash,
    );

    // Promote "tool not registered" denials to a typed error so callers
    // can fix it at the registration site instead of treating it as a
    // policy decision they could relax. Must run before the generic
    // ClampdBlockedError throw below.
    raiseIfUnregistered(toolName, proxyRes);

    if (!proxyRes.allowed && blockOnDeny) {
      throwBlockedOrLoop(client, proxyRes);
    }

    // Allowed (or blockOnDeny=false) — execute the original function.
    if (proxyRes.allowed && proxyRes.scope_token) {
      setScopeToken(proxyRes.scope_token);
      return withScopeToken(proxyRes.scope_token, () => fn(...args));
    }
    return fn(...args);
  };
}

// ── Pattern B: wrapOpenAITools ────────────────────────────────────

export interface WrapOpenAIToolsOptions {
  /** ClampdClient instance for proxy calls. */
  client: ClampdClient;

  /**
   * Upstream tool URL forwarded to the Clampd pipeline.
   * Defaults to "" (verify-only).
   */
  targetUrl?: string;

  /**
   * When `true` (default), a denied proxy response throws
   * `ClampdBlockedError` instead of executing the tool function.
   */
  blockOnDeny?: boolean;
}

/**
 * Wrap an array of OpenAI-style tool definitions so that each tool's
 * `execute` function is intercepted through the Clampd proxy.
 *
 * Tools without an `execute` function are returned unchanged.
 *
 * ```ts
 * const guardedTools = wrapOpenAITools(tools, { client, targetUrl: "http://tool:5555" });
 * ```
 */
export function wrapOpenAITools(
  tools: OpenAITool[],
  opts: WrapOpenAIToolsOptions,
): OpenAITool[] {
  const { client, targetUrl = "", blockOnDeny = true } = opts;

  return tools.map((tool) => {
    const originalExecute = tool.function.execute;

    // If the tool has no execute handler there is nothing to intercept.
    if (typeof originalExecute !== "function") {
      return tool;
    }

    const descriptorHash = contractHash({
      name: tool.function.name,
      description: tool.function.description ?? "",
      parameters: (tool.function.parameters as object) ?? {},
    });

    const wrappedExecute = async (
      args: Record<string, unknown>,
    ): Promise<unknown> => {
      const proxyRes = await client.proxy(
        tool.function.name,
        args,
        targetUrl,
        undefined,
        descriptorHash,
      );

      raiseIfUnregistered(tool.function.name, proxyRes);

      if (!proxyRes.allowed && blockOnDeny) {
        throwBlockedOrLoop(client, proxyRes);
      }

      if (proxyRes.allowed && proxyRes.scope_token) {
        setScopeToken(proxyRes.scope_token);
        return withScopeToken(proxyRes.scope_token, () => originalExecute(args));
      }
      return originalExecute(args);
    };

    // Return a shallow copy so we do not mutate the caller's array.
    return {
      ...tool,
      function: {
        ...tool.function,
        execute: wrappedExecute,
      },
    };
  });
}

// ── Pattern C: ClampdGuard ────────────────────────────────────────

export interface ClampdGuardOptions {
  /**
   * Default target URL for proxy calls. Individual `execute()` calls
   * can override this.
   */
  defaultTargetUrl?: string;
}

/**
 * Framework-agnostic guard that can pre-check or fully execute any
 * tool call through the Clampd pipeline.
 *
 * ```ts
 * const guard = new ClampdGuard(client, { defaultTargetUrl: "http://tool:5555" });
 *
 * // Dry-run check only
 * const res = await guard.check("http.fetch", { url: "https://evil.com" });
 * if (!res.allowed) console.log("Denied:", res.denial_reason);
 *
 * // Full pipeline: check + execute
 * const { result, proxyResponse } = await guard.execute(
 *   "http.fetch",
 *   { url: "https://api.example.com" },
 *   () => fetch("https://api.example.com").then(r => r.json()),
 * );
 * ```
 */
export class ClampdGuard {
  private readonly client: ClampdClient;
  private readonly defaultTargetUrl: string;

  constructor(client: ClampdClient, opts?: ClampdGuardOptions) {
    this.client = client;
    this.defaultTargetUrl = opts?.defaultTargetUrl ?? "";
  }

  /**
   * Dry-run policy check via the gateway's `/v1/verify` endpoint.
   * No token exchange or upstream forwarding occurs.
   */
  async check(
    tool: string,
    params: Record<string, unknown>,
  ): Promise<ProxyResponse> {
    return this.client.verify(tool, params);
  }

  /**
   * Full security pipeline: send the call through `/v1/proxy` and, if
   * allowed, execute the provided function.
   *
   * Throws `ClampdBlockedError` when the proxy denies the call.
   *
   * @returns An object containing both the function result and the raw
   *          `ProxyResponse` from the gateway.
   */
  async execute<T>(
    tool: string,
    params: Record<string, unknown>,
    fn: () => Promise<T>,
    targetUrl?: string,
    opts?: { description?: string; paramSchema?: Record<string, unknown> },
  ): Promise<{ result: T; proxyResponse: ProxyResponse }> {
    const url = targetUrl ?? this.defaultTargetUrl;

    const descriptorHash =
      opts && (opts.description !== undefined || opts.paramSchema !== undefined)
        ? contractHash({
            name: tool,
            description: opts.description ?? "",
            parameters: (opts.paramSchema as object) ?? {},
          })
        : undefined;

    const proxyResponse = await this.client.proxy(
      tool,
      params,
      url,
      undefined,
      descriptorHash,
    );

    raiseIfUnregistered(tool, proxyResponse);

    if (!proxyResponse.allowed) {
      throwBlockedOrLoop(this.client, proxyResponse);
    }

    if (proxyResponse.scope_token) {
      setScopeToken(proxyResponse.scope_token);
      const result = await withScopeToken(proxyResponse.scope_token, fn);
      return { result, proxyResponse };
    }

    const result = await fn();
    return { result, proxyResponse };
  }
}
