import { describe, it, expect, vi, beforeEach } from "vitest";
import { getDelegation, withDelegation } from "../delegation.js";

// All tests need a signing secret since unsigned JWTs are rejected
process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

/**
 * These tests verify delegation context propagation in the MCP proxy.
 *
 * Since the ClampdMCPProxy requires the @modelcontextprotocol/sdk peer
 * dependency (which may not be installed in test), we test the delegation
 * integration pattern directly using the delegation module functions.
 */

function mockGatewayResponse(allowed = true) {
  return {
    request_id: "req-test",
    allowed,
    risk_score: allowed ? 0.1 : 0.95,
    denial_reason: allowed ? null : "blocked",
    latency_ms: 5,
    degraded_stages: [],
    session_flags: [],
    scope_granted: allowed ? "data:read" : null,
  };
}

describe("MCP delegation context propagation", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("withDelegation sets context for single agent (no parent)", async () => {
    let capturedCtx = getDelegation();
    expect(capturedCtx).toBeUndefined();

    await withDelegation("agent-b-uuid", () => {
      capturedCtx = getDelegation();
    });

    expect(capturedCtx).toBeDefined();
    expect(capturedCtx!.chain).toEqual(["agent-b-uuid"]);
    expect(capturedCtx!.traceId).toBeTruthy();

    // Context cleaned up after withDelegation returns
    expect(getDelegation()).toBeUndefined();
  });

  it("nested withDelegation builds parent -> child chain", async () => {
    let capturedCtx: ReturnType<typeof getDelegation>;

    await withDelegation("agent-a-uuid", () =>
      withDelegation("agent-b-uuid", () => {
        capturedCtx = getDelegation();
      }),
    );

    expect(capturedCtx!).toBeDefined();
    expect(capturedCtx!.chain).toEqual(["agent-a-uuid", "agent-b-uuid"]);
    expect(capturedCtx!.traceId).toBeTruthy();

    // Context cleaned up
    expect(getDelegation()).toBeUndefined();
  });

  it("nested delegation preserves parent trace ID", async () => {
    let parentTraceId: string | undefined;
    let childTraceId: string | undefined;

    await withDelegation("agent-a-uuid", () => {
      parentTraceId = getDelegation()?.traceId;
      return withDelegation("agent-b-uuid", () => {
        childTraceId = getDelegation()?.traceId;
      });
    });

    expect(parentTraceId).toBeTruthy();
    expect(childTraceId).toBe(parentTraceId);
  });

  it("separate calls get different trace IDs", async () => {
    const traceIds: string[] = [];

    await withDelegation("agent-a-uuid", () => {
      traceIds.push(getDelegation()!.traceId);
    });

    await withDelegation("agent-a-uuid", () => {
      traceIds.push(getDelegation()!.traceId);
    });

    expect(traceIds).toHaveLength(2);
    expect(traceIds[0]).not.toBe(traceIds[1]);
  });

  it("simulates MCP proxy gateway call with delegation fields", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockGatewayResponse(true),
    });
    vi.stubGlobal("fetch", mockFetch);

    // Simulate what the MCP proxy does: wrap gateway call in delegation context
    const agentId = "agent-b-uuid";
    const parentAgentId = "agent-a-uuid";

    await withDelegation(parentAgentId, () =>
      withDelegation(agentId, async () => {
        const delegation = getDelegation();
        const body: Record<string, unknown> = {
          tool: "read_file",
          params: { path: "/tmp/test" },
          target_url: "",
          prompt_context: "MCP tool call: read_file",
        };

        // Include delegation fields (as the MCP proxy does)
        if (delegation && delegation.chain.length >= 2) {
          body.caller_agent_id = delegation.chain[delegation.chain.length - 2];
          body.delegation_chain = delegation.chain;
          body.delegation_trace_id = delegation.traceId;
        }

        await fetch("http://test:8080/v1/proxy", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      }),
    );

    expect(mockFetch).toHaveBeenCalledOnce();
    const fetchBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(fetchBody.caller_agent_id).toBe("agent-a-uuid");
    expect(fetchBody.delegation_chain).toEqual(["agent-a-uuid", "agent-b-uuid"]);
    expect(fetchBody.delegation_trace_id).toBeTruthy();
  });

  it("simulates MCP proxy without parent (no delegation fields)", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockGatewayResponse(true),
    });
    vi.stubGlobal("fetch", mockFetch);

    const agentId = "agent-b-uuid";

    await withDelegation(agentId, async () => {
      const delegation = getDelegation();
      const body: Record<string, unknown> = {
        tool: "read_file",
        params: { path: "/tmp/test" },
        target_url: "",
      };

      // Only include delegation fields when chain has >= 2 entries
      if (delegation && delegation.chain.length >= 2) {
        body.caller_agent_id = delegation.chain[delegation.chain.length - 2];
        body.delegation_chain = delegation.chain;
        body.delegation_trace_id = delegation.traceId;
      }

      await fetch("http://test:8080/v1/proxy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const fetchBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    // No parent, so no delegation fields should be present
    expect(fetchBody.caller_agent_id).toBeUndefined();
    expect(fetchBody.delegation_chain).toBeUndefined();
    expect(fetchBody.delegation_trace_id).toBeUndefined();
  });

  it("context is cleaned up even on error", async () => {
    try {
      await withDelegation("agent-a-uuid", () => {
        throw new Error("simulated failure");
      });
    } catch {
      // expected
    }

    expect(getDelegation()).toBeUndefined();
  });
});
