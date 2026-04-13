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
import { setScopeToken, withScopeToken } from "./tool-verify.js";

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
 */
export class ClampdBlockedError extends Error {
  public readonly response: ProxyResponse;
  public readonly matchedRules: string[];
  public readonly sessionFlags: string[];

  constructor(response: ProxyResponse) {
    const parts = [
      `Blocked: ${response.denial_reason ?? "unknown reason"} (risk=${response.risk_score.toFixed(2)})`,
    ];
    if (response.matched_rules?.length) {
      parts.push(`rules: ${response.matched_rules.join(", ")}`);
    }
    if (response.session_flags?.length) {
      parts.push(`session: ${response.session_flags.join(", ")}`);
    }
    super(parts.join(" | "));
    this.name = "ClampdBlockedError";
    this.response = response;
    this.matchedRules = response.matched_rules ?? [];
    this.sessionFlags = response.session_flags ?? [];
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
  } = opts;

  return async (...args: TArgs): Promise<TReturn> => {
    const params = paramExtractor
      ? paramExtractor(...args)
      : defaultExtractParams(args as unknown[]);

    const proxyRes = await client.proxy(
      toolName,
      params,
      targetUrl,
      promptContext,
    );

    if (!proxyRes.allowed && blockOnDeny) {
      throw new ClampdBlockedError(proxyRes);
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

    const wrappedExecute = async (
      args: Record<string, unknown>,
    ): Promise<unknown> => {
      const proxyRes = await client.proxy(
        tool.function.name,
        args,
        targetUrl,
      );

      if (!proxyRes.allowed && blockOnDeny) {
        throw new ClampdBlockedError(proxyRes);
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
  ): Promise<{ result: T; proxyResponse: ProxyResponse }> {
    const url = targetUrl ?? this.defaultTargetUrl;

    const proxyResponse = await this.client.proxy(tool, params, url);

    if (!proxyResponse.allowed) {
      throw new ClampdBlockedError(proxyResponse);
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
