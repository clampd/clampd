/**
 * ClampdClient — thin wrapper around the ag-gateway HTTP API.
 */

import { makeAgentJwt } from "./auth.js";
import { getDelegation, delegationHeaders } from "./delegation.js";

// ── Response types ─────────────────────────────────────────────────

export interface ProxyResponse {
  request_id: string;
  allowed: boolean;
  /** Intent action: "pass", "flag", or "block". */
  action?: string;
  risk_score: number;
  scope_granted?: string | null;
  tool_response?: unknown | null;
  denial_reason?: string | null;
  /** Human-readable explanation of the risk assessment. */
  reasoning?: string | null;
  /** Rule IDs that matched this request (e.g. ["R001", "R005"]). */
  matched_rules?: string[];
  latency_ms: number;
  degraded_stages: string[];
  session_flags: string[];
  /** HMAC scope token binding this approval to response scanning. */
  scope_token?: string | null;
}

export interface ScanResponse {
  allowed: boolean;
  risk_score: number;
  denial_reason?: string;
  matched_rules: string[];
  latency_ms: number;
}

export interface ScanOutputResponse extends ScanResponse {
  pii_found: Array<{ pii_type: string; count: number }>;
  secrets_found: Array<{ secret_type: string; count: number }>;
}

// ── Request types ──────────────────────────────────────────────────

export interface ProxyRequest {
  tool: string;
  params: Record<string, unknown>;
  target_url: string;
  prompt_context?: string;
}

export interface VerifyRequest {
  tool: string;
  params: Record<string, unknown>;
  target_url?: string;
}

// ── Client options ─────────────────────────────────────────────────

export interface CircuitBreakerOptions {
  /** Number of consecutive failures before opening the circuit. Default: 5. */
  threshold?: number;
  /** Time in ms to keep circuit open before allowing a probe. Default: 30000. */
  resetTimeoutMs?: number;
}

export interface RetryOptions {
  /** Max retry attempts (0 = no retries). Default: 0. */
  maxRetries?: number;
  /** Base delay in ms for exponential backoff. Default: 500. */
  baseDelayMs?: number;
}

export interface ClampdClientOptions {
  gatewayUrl?: string;
  agentId: string;
  apiKey?: string;
  secret?: string;
  timeoutMs?: number;
  /** Retry options for transient gateway errors. */
  retry?: RetryOptions;
  /** Circuit breaker to avoid hammering a failing gateway. */
  circuitBreaker?: CircuitBreakerOptions;
}

// ── Synthesized error response ─────────────────────────────────────

function blockedResponse(reason: string, gatewayError = false): ProxyResponse {
  return {
    request_id: "error",
    allowed: false,
    risk_score: 1.0,
    denial_reason: reason,
    matched_rules: [],
    latency_ms: 0,
    degraded_stages: [],
    session_flags: [],
    _gatewayError: gatewayError,
  } as ProxyResponse;
}

// ── Client ─────────────────────────────────────────────────────────

/**
 * Synchronous-style (async/await) client for the Clampd gateway proxy API.
 *
 * Uses the built-in `fetch` available in Node 18+.
 */
export class ClampdClient {
  private readonly gatewayUrl: string;
  public readonly agentId: string;
  private readonly apiKey: string;
  private readonly jwt: string;
  private readonly timeoutMs: number;

  // Retry config
  private readonly maxRetries: number;
  private readonly baseDelayMs: number;

  // Circuit breaker state
  private readonly cbThreshold: number;
  private readonly cbResetTimeoutMs: number;
  private cbFailures: number = 0;
  private cbOpenedAt: number = 0;
  private cbState: "closed" | "open" | "half-open" = "closed";

  constructor(opts: ClampdClientOptions) {
    this.gatewayUrl = (opts.gatewayUrl ?? "http://localhost:8080").replace(
      /\/$/,
      "",
    );
    this.agentId = opts.agentId;
    this.apiKey = opts.apiKey ?? process.env.CLAMPD_API_KEY ?? "";
    this.jwt = makeAgentJwt(this.agentId, { secret: opts.secret });
    this.timeoutMs = opts.timeoutMs ?? 30_000;

    // Retry
    this.maxRetries = opts.retry?.maxRetries ?? 0;
    this.baseDelayMs = opts.retry?.baseDelayMs ?? 500;

    // Circuit breaker
    this.cbThreshold = opts.circuitBreaker?.threshold ?? 5;
    this.cbResetTimeoutMs = opts.circuitBreaker?.resetTimeoutMs ?? 30_000;
  }

  /** Check if circuit breaker allows a request. */
  private cbAllowRequest(): boolean {
    if (this.cbState === "closed") return true;
    if (this.cbState === "open") {
      if (Date.now() - this.cbOpenedAt >= this.cbResetTimeoutMs) {
        this.cbState = "half-open";
        return true; // Allow one probe request
      }
      return false;
    }
    // half-open: already allowing one probe
    return true;
  }

  /** Record a successful request. */
  private cbRecordSuccess(): void {
    this.cbFailures = 0;
    this.cbState = "closed";
  }

  /** Record a failed request. */
  private cbRecordFailure(): void {
    this.cbFailures++;
    if (this.cbFailures >= this.cbThreshold) {
      this.cbState = "open";
      this.cbOpenedAt = Date.now();
    }
  }

  private headers(tools?: string[]): Record<string, string> {
    const h: Record<string, string> = {
      Authorization: `Bearer ${this.jwt}`,
      "X-AG-Key": this.apiKey,
      "Content-Type": "application/json",
      ...delegationHeaders(),
    };
    if (tools && tools.length > 0) {
      h["X-AG-Authorized-Tools"] = tools.join(",");
    }
    return h;
  }

  /**
   * Send a tool call through the Clampd gateway for evaluation.
   *
   * When targetUrl is empty (default), the gateway runs evaluate-only mode:
   * classify + policy check, no token exchange or forwarding. The tool
   * executes locally in the agent's runtime.
   *
   * When targetUrl is set, the gateway also exchanges a micro-token and
   * forwards the request to the target, inspecting the response.
   */
  async proxy(
    tool: string,
    params: Record<string, unknown>,
    targetUrl: string = "",
    promptContext?: string,
    toolDescriptorHash?: string,
    authorizedTools?: string[],
  ): Promise<ProxyResponse> {
    const body: Record<string, unknown> = {
      tool,
      params,
      target_url: targetUrl,
    };
    if (promptContext) {
      body.prompt_context = promptContext;
    }
    if (toolDescriptorHash) {
      body.tool_descriptor_hash = toolDescriptorHash;
    }

    // Auto-include delegation context only for real cross-agent delegation.
    // Single-element chain = agent calling itself = not delegation.
    const delegation = getDelegation();
    if (delegation && delegation.chain.length > 1) {
      body.delegation_chain = delegation.chain;
      body.delegation_trace_id = delegation.traceId;
    }

    return this.post("/v1/proxy", body, authorizedTools);
  }

  /**
   * Get delegation headers for cross-service HTTP propagation.
   * Static convenience method.
   */
  static delegationHeaders(): Record<string, string> {
    return delegationHeaders();
  }

  /**
   * Inspect a tool response for PII, anomalies, or policy violations.
   *
   * When scopeToken is provided (from a prior proxy() call),
   * the gateway can verify this response came from a Clampd-approved call.
   */
  async inspect(
    tool: string,
    responseData: unknown,
    requestId?: string,
    scopeToken?: string,
  ): Promise<ProxyResponse> {
    const body: Record<string, unknown> = { tool, response_data: responseData };
    if (requestId) body.request_id = requestId;
    if (scopeToken) body.scope_token = scopeToken;
    return this.post("/v1/inspect", body);
  }

  /**
   * Dry-run: stages 1-6 only — no token exchange or forwarding.
   */
  async verify(
    tool: string,
    params: Record<string, unknown>,
    targetUrl: string = "",
  ): Promise<ProxyResponse> {
    const body: VerifyRequest = {
      tool,
      params,
      target_url: targetUrl,
    };

    return this.post("/v1/verify", body as unknown as Record<string, unknown>);
  }

  /**
   * Scan input text (prompt) for injection attacks, jailbreaks, etc.
   * Unlike proxy/verify, this throws on network errors so callers can
   * implement fail-open vs fail-closed logic.
   */
  async scanInput(text: string, messageCount?: number): Promise<ScanResponse> {
    const body: Record<string, unknown> = { text };
    if (messageCount) body.message_count = messageCount;
    return this.postOrThrow<ScanResponse>("/v1/scan-input", body);
  }

  /**
   * Scan output text (LLM response) for PII, secrets, policy violations.
   * Unlike proxy/verify, this throws on network errors so callers can
   * implement fail-open vs fail-closed logic.
   */
  async scanOutput(text: string, requestId?: string): Promise<ScanOutputResponse> {
    const body: Record<string, unknown> = { text };
    if (requestId) body.request_id = requestId;
    return this.postOrThrow<ScanOutputResponse>("/v1/scan-output", body);
  }

  // ── Internal ────────────────────────────────────────────────────

  private async post<T = ProxyResponse>(
    path: string,
    body: Record<string, unknown>,
    authorizedTools?: string[],
  ): Promise<T> {
    // Circuit breaker check
    if (!this.cbAllowRequest()) {
      return blockedResponse(
        "Circuit breaker open: gateway unavailable, requests are being short-circuited",
        true,
      ) as unknown as T;
    }

    const url = `${this.gatewayUrl}${path}`;
    let lastError: string = "";

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 500ms, 1000ms, 2000ms, ...
        const delay = this.baseDelayMs * Math.pow(2, attempt - 1);
        await new Promise((r) => setTimeout(r, delay));
      }

      let resp: Response;
      try {
        resp = await fetch(url, {
          method: "POST",
          headers: this.headers(authorizedTools),
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (err: unknown) {
        lastError = err instanceof Error ? err.message : "Unknown fetch error";
        this.cbRecordFailure();
        continue; // Retry on network errors
      }

      if (resp.ok) {
        this.cbRecordSuccess();
        const json = (await resp.json()) as T;
        // Ensure array fields are always present for ProxyResponse shape
        if (typeof json === "object" && json !== null && "degraded_stages" in json) {
          const pr = json as unknown as ProxyResponse;
          return {
            ...json,
            degraded_stages: pr.degraded_stages ?? [],
            session_flags: pr.session_flags ?? [],
          };
        }
        return json;
      }

      // Don't retry on 4xx client errors (except 429 rate limit)
      if (resp.status >= 400 && resp.status < 500 && resp.status !== 429) {
        this.cbRecordSuccess(); // Client error is not a gateway failure
        let errorText = await resp.text().catch(() => `HTTP ${resp.status}`);
        if (
          resp.status === 401 &&
          (errorText.includes("InvalidSignature") || errorText.includes("JWT validation failed"))
        ) {
          errorText =
            "agent_auth_failed: Agent authentication failed. This usually means the agent is suspended " +
            "or the signing secret is incorrect. Check your agent status in the dashboard " +
            "or verify JWT_SECRET / secret parameter.";
        }
        return blockedResponse(errorText, true) as unknown as T;
      }

      // 5xx or 429 — retry
      lastError = await resp.text().catch(() => `HTTP ${resp.status}`);
      this.cbRecordFailure();
    }

    // All retries exhausted
    return blockedResponse(`Fetch error: ${lastError}`, true) as unknown as T;
  }

  /**
   * Like `post`, but throws on network errors and non-OK responses
   * instead of synthesizing a blocked response. Used by scan methods
   * so callers can distinguish gateway errors from policy decisions.
   */
  private async postOrThrow<T>(
    path: string,
    body: Record<string, unknown>,
  ): Promise<T> {
    const url = `${this.gatewayUrl}${path}`;

    let resp: Response;
    try {
      resp = await fetch(url, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Scan fetch error: ${message}`);
    }

    if (!resp.ok) {
      const text = await resp.text().catch(() => `HTTP ${resp.status}`);
      throw new Error(`Scan request failed: ${text}`);
    }

    return (await resp.json()) as T;
  }
}
