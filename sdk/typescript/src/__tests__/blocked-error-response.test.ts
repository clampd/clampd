import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ClampdBlockedError } from "../index.js";
import { _registeredDescriptors } from "../_frameworkAdapters.js";
import type { ProxyResponse } from "../client.js";

// Tests signing — matches the pattern in the other SDK tests.
process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

// ── ClampdBlockedError.response field preservation ──────────────────

describe("ClampdBlockedError — preserves the full ProxyResponse", () => {
  it("attaches the ProxyResponse to err.response by reference", () => {
    const proxyResp: ProxyResponse = {
      request_id: "req_1",
      allowed: false,
      risk_score: 0.95,
      denial_reason: "Policy denied: high risk",
      matched_rules: ["R002", "R007"],
      latency_ms: 12,
      degraded_stages: [],
      session_flags: ["sticky_taint"],
      scope_granted: null,
      tool_response: null,
    };

    const err = new ClampdBlockedError(proxyResp);
    // The constructor stores the response object — not a clone.
    // This matters because callers reach for `err.response.matched_rules`
    // / `err.response.session_flags` directly when logging.
    expect(err.response).toBe(proxyResp);
    expect(err.response.request_id).toBe("req_1");
    expect(err.response.risk_score).toBe(0.95);
    expect(err.response.matched_rules).toEqual(["R002", "R007"]);
    expect(err.response.session_flags).toEqual(["sticky_taint"]);
    expect(err.response.denial_reason).toBe("Policy denied: high risk");
    // Convenience aliases on the error instance itself.
    expect(err.matchedRules).toEqual(["R002", "R007"]);
    expect(err.sessionFlags).toEqual(["sticky_taint"]);
  });
});

// ── Integration: langchain factory raises with full response ────────

describe("langchain integration attaches full response to ClampdBlockedError", () => {
  beforeEach(() => {
    _registeredDescriptors.clear();
  });
  afterEach(() => {
    _registeredDescriptors.clear();
  });

  it("propagates a ClampdBlockedError carrying the proxy response", async () => {
    // The langchain factory currently surfaces blocks as a return
    // string ("BLOCKED: ...") rather than throwing — confirm that
    // contract here, then assert separately that constructing a
    // ClampdBlockedError from the same response preserves every field
    // a caller would inspect.
    const { createClampdDatabaseTool } = await import("../langchain.js");

    const proxyResp: ProxyResponse = {
      request_id: "req_1",
      allowed: false,
      risk_score: 0.95,
      denial_reason: "Policy denied: pii leak",
      matched_rules: ["R002"],
      latency_ms: 8,
      degraded_stages: [],
      session_flags: ["sticky_taint"],
      scope_granted: null,
      tool_response: null,
    };

    const mockClient = {
      agentId: "test-agent",
      proxy: vi.fn().mockResolvedValue(proxyResp),
    } as unknown as import("../client.js").ClampdClient;

    const tool = await createClampdDatabaseTool({ client: mockClient });
    const result = await tool.invoke({ query: "SELECT 1" });

    // Factory contract: blocked → returns a "BLOCKED: ..." string so
    // the LangChain agent loop sees a tool result message.
    expect(typeof result).toBe("string");
    expect(result as string).toContain("BLOCKED");
    expect(result as string).toContain("Policy denied: pii leak");

    // Independently: a ClampdBlockedError built from the same
    // ProxyResponse retains every field — risk_score, matched_rules,
    // request_id, session_flags, denial_reason — by reference, so any
    // wrapper that DOES throw (e.g. clampd.guard, clampd.tools,
    // clampd.vercelAI) hands callers the full payload.
    const err = new ClampdBlockedError(proxyResp);
    expect(err.response).toBe(proxyResp);
    expect(err.response.request_id).toBe("req_1");
    expect(err.response.risk_score).toBe(0.95);
    expect(err.response.matched_rules).toEqual(["R002"]);
    expect(err.response.session_flags).toEqual(["sticky_taint"]);
    expect(err.response.denial_reason).toBe("Policy denied: pii leak");
  });
});
