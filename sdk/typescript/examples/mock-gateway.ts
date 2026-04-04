/**
 * Mock Clampd Gateway — drop-in replacement for testing without a real gateway.
 *
 * Usage:
 *   import { installMockGateway, removeMockGateway } from "./mock-gateway.js";
 *
 *   // Install before running examples
 *   installMockGateway();
 *
 *   // ... run your code ...
 *
 *   // Remove when done (optional)
 *   removeMockGateway();
 *
 * To switch to a real gateway, simply remove the installMockGateway() call
 * and set environment variables:
 *   CLAMPD_GATEWAY_URL=https://your-gateway.clampd.dev
 *   CLAMPD_API_KEY=your-api-key
 */

// Set JWT_SECRET for mock mode (not needed with a real gateway that validates JWTs)
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = "mock-secret-for-local-testing-32ch!";
}

// Configurable blocked tool patterns — add patterns to simulate blocking
const BLOCKED_TOOLS = new Set([
  "rm_rf", "exec_shell", "delete_database", "drop_table",
]);

const BLOCKED_INPUT_PATTERNS = [
  /ignore\s+(previous|all)\s+instructions/i,
  /drop\s+table/i,
  /rm\s+-rf/i,
];

let originalFetch: typeof globalThis.fetch | null = null;

export function installMockGateway(): void {
  originalFetch = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init?.body ? JSON.parse(init.body as string) : {};

    // ── /v1/proxy ──
    if (url.includes("/v1/proxy")) {
      const tool = body.tool as string;
      const isBlocked = BLOCKED_TOOLS.has(tool);
      return new Response(JSON.stringify({
        request_id: `mock-${Date.now()}`,
        allowed: !isBlocked,
        action: isBlocked ? "block" : "pass",
        risk_score: isBlocked ? 0.95 : 0.05,
        denial_reason: isBlocked ? `Tool '${tool}' is blocked by security policy` : null,
        reasoning: isBlocked ? "High-risk tool detected" : "Low risk, approved",
        matched_rules: isBlocked ? ["R001"] : [],
        latency_ms: 3,
        degraded_stages: [],
        session_flags: [],
        scope_token: isBlocked ? null : "mock-scope-token",
      }), { status: 200 });
    }

    // ── /v1/verify ──
    if (url.includes("/v1/verify")) {
      return new Response(JSON.stringify({
        request_id: `mock-verify-${Date.now()}`,
        allowed: true,
        risk_score: 0.05,
        latency_ms: 2,
        degraded_stages: [],
        session_flags: [],
      }), { status: 200 });
    }

    // ── /v1/inspect ──
    if (url.includes("/v1/inspect")) {
      return new Response(JSON.stringify({
        request_id: `mock-inspect-${Date.now()}`,
        allowed: true,
        risk_score: 0.1,
        latency_ms: 2,
        degraded_stages: [],
        session_flags: [],
      }), { status: 200 });
    }

    // ── /v1/scan-input ──
    if (url.includes("/v1/scan-input")) {
      const text = body.text as string;
      const isBlocked = BLOCKED_INPUT_PATTERNS.some(p => p.test(text));
      return new Response(JSON.stringify({
        allowed: !isBlocked,
        risk_score: isBlocked ? 0.92 : 0.03,
        denial_reason: isBlocked ? "Prompt injection detected" : null,
        matched_rules: isBlocked ? ["SCAN-001"] : [],
        latency_ms: 2,
      }), { status: 200 });
    }

    // ── /v1/scan-output ──
    if (url.includes("/v1/scan-output")) {
      return new Response(JSON.stringify({
        allowed: true,
        risk_score: 0.02,
        denial_reason: null,
        matched_rules: [],
        latency_ms: 2,
        pii_found: [],
        secrets_found: [],
      }), { status: 200 });
    }

    // Fall through to original fetch for non-gateway requests
    if (originalFetch) return originalFetch(input, init);
    throw new Error(`Mock gateway: unhandled URL ${url}`);
  }) as typeof globalThis.fetch;
}

export function removeMockGateway(): void {
  if (originalFetch) {
    globalThis.fetch = originalFetch;
    originalFetch = null;
  }
}
