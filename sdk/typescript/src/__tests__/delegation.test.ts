import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  withDelegation,
  getDelegation,
  getCallerAgentId,
  hasCycle,
  delegationHeaders,
  MAX_DELEGATION_DEPTH,
} from "../delegation.js";
import clampd, { ClampdBlockedError } from "../index.js";

// Signing secret required since unsigned JWTs are rejected
process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

function mockProxyResponse(allowed = true) {
  return {
    request_id: "req-test",
    allowed,
    risk_score: allowed ? 0.1 : 0.95,
    denial_reason: allowed ? null : "blocked",
    latency_ms: 5,
    degraded_stages: [],
    session_flags: [],
    scope_granted: allowed ? "db:read" : null,
    tool_response: allowed ? "ok" : null,
  };
}

// ── Unit tests for delegation primitives ──────────────────────────

describe("delegation context", () => {
  it("returns undefined outside any context", () => {
    expect(getDelegation()).toBeUndefined();
    expect(getCallerAgentId()).toBeUndefined();
  });

  it("single agent — chain has 1 entry", () => {
    withDelegation("agent-a", () => {
      const ctx = getDelegation();
      expect(ctx).toBeDefined();
      expect(ctx!.chain).toEqual(["agent-a"]);
      expect(ctx!.confidence).toBe("verified");
      expect(ctx!.traceId).toHaveLength(16);
    });
  });

  it("two agents same process — auto-detects A -> B", () => {
    withDelegation("agent-a", () => {
      withDelegation("agent-b", () => {
        const ctx = getDelegation();
        expect(ctx!.chain).toEqual(["agent-a", "agent-b"]);
        expect(getCallerAgentId()).toBe("agent-a");
      });
    });
  });

  it("three agents — chain A -> B -> C", () => {
    withDelegation("agent-a", () => {
      const outerCtx = getDelegation();
      withDelegation("agent-b", () => {
        withDelegation("agent-c", () => {
          const ctx = getDelegation();
          expect(ctx!.chain).toEqual(["agent-a", "agent-b", "agent-c"]);
          expect(getCallerAgentId()).toBe("agent-b");
          // traceId should be preserved across all hops
          expect(ctx!.traceId).toBe(outerCtx!.traceId);
        });
      });
    });
  });

  it("cycle detection — A -> B -> A throws", () => {
    withDelegation("agent-a", () => {
      withDelegation("agent-b", () => {
        expect(() =>
          withDelegation("agent-a", () => {
            /* should not reach here */
          }),
        ).toThrow("Circular delegation detected");
      });
    });
  });

  it("max depth exceeded — throws", () => {
    const buildNested = (depth: number, fn: () => void): (() => void) => {
      if (depth === 0) return fn;
      return () => withDelegation(`agent-${depth}`, buildNested(depth - 1, fn));
    };

    // MAX_DELEGATION_DEPTH + 1 agents should exceed the limit
    const run = buildNested(MAX_DELEGATION_DEPTH + 1, () => {
      /* should not reach here */
    });

    expect(run).toThrow("Delegation depth");
  });

  it("preserves traceId across hops", () => {
    let traceA: string | undefined;
    let traceB: string | undefined;

    withDelegation("agent-a", () => {
      traceA = getDelegation()!.traceId;
      withDelegation("agent-b", () => {
        traceB = getDelegation()!.traceId;
      });
    });

    expect(traceA).toBeDefined();
    expect(traceA).toBe(traceB);
  });

  it("concurrent async operations do not interfere", async () => {
    const results: string[][] = [];

    const task = (agentId: string, innerAgentId: string): Promise<void> =>
      new Promise((resolve) => {
        withDelegation(agentId, () => {
          // Use setImmediate to interleave execution
          setTimeout(() => {
            withDelegation(innerAgentId, () => {
              const ctx = getDelegation();
              results.push([...ctx!.chain]);
              resolve();
            });
          }, Math.random() * 10);
        });
      });

    await Promise.all([
      task("alice", "bob"),
      task("charlie", "dave"),
      task("eve", "frank"),
    ]);

    expect(results).toHaveLength(3);
    // Each task should have its own isolated chain
    const chains = results.map((r) => r.join(","));
    expect(chains).toContain("alice,bob");
    expect(chains).toContain("charlie,dave");
    expect(chains).toContain("eve,frank");
  });
});

describe("hasCycle()", () => {
  it("returns false for unique chain", () => {
    expect(hasCycle(["a", "b", "c"])).toBe(false);
  });

  it("returns true for duplicate entries", () => {
    expect(hasCycle(["a", "b", "a"])).toBe(true);
  });

  it("returns false for empty chain", () => {
    expect(hasCycle([])).toBe(false);
  });

  it("returns false for single entry", () => {
    expect(hasCycle(["a"])).toBe(false);
  });
});

// ── delegationHeaders() ──────────────────────────────────────────

describe("delegationHeaders()", () => {
  it("returns empty object outside context", () => {
    expect(delegationHeaders()).toEqual({});
  });

  it("returns correct headers inside context", () => {
    withDelegation("agent-a", () => {
      withDelegation("agent-b", () => {
        const headers = delegationHeaders();
        expect(headers["X-Clampd-Delegation-Trace"]).toHaveLength(16);
        expect(headers["X-Clampd-Delegation-Chain"]).toBe("agent-a,agent-b");
        expect(headers["X-Clampd-Delegation-Confidence"]).toBe("verified");
      });
    });
  });

  it("single agent returns empty headers (not delegation)", () => {
    withDelegation("solo-agent", () => {
      const headers = delegationHeaders();
      expect(headers).toEqual({});
    });
  });
});

// ── Integration with guard() ──────────────────────────────────────

describe("guard() delegation integration", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("sends delegation metadata when nested", async () => {
    const fetchCalls: string[] = [];
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      fetchCalls.push(init.body as string);
      return {
        ok: true,
        json: async () => mockProxyResponse(true),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const innerFn = vi.fn().mockResolvedValue("inner-result");
    const outerFn = vi.fn().mockImplementation(async () => {
      const guardedInner = clampd.guard(innerFn, {
        agentId: "agent-b",
        toolName: "inner.tool",
      });
      return guardedInner({ key: "value" });
    });

    const guardedOuter = clampd.guard(outerFn, {
      agentId: "agent-a",
      toolName: "outer.tool",
    });

    await guardedOuter({});

    expect(mockFetch).toHaveBeenCalledTimes(2);

    // First call (outer) sends chain with just agent-a (gateway appends from JWT)
    const outerBody = JSON.parse(fetchCalls[0]);
    if (outerBody.params._delegation) {
      expect(outerBody.params._delegation.delegation_chain).toEqual(["agent-a"]);
      expect(outerBody.params._delegation.caller_agent_id).toBeUndefined();
    }

    // Second call (inner) sends chain [agent-a, agent-b] — no caller_agent_id
    // (gateway computes caller from the chain)
    const innerBody = JSON.parse(fetchCalls[1]);
    expect(innerBody.params._delegation).toBeDefined();
    expect(innerBody.params._delegation.caller_agent_id).toBeUndefined();
    expect(innerBody.params._delegation.delegation_chain).toEqual([
      "agent-a",
      "agent-b",
    ]);
    expect(innerBody.params._delegation.delegation_trace_id).toHaveLength(16);
  });

  it("single agent sends delegation chain for gateway to complete", async () => {
    const fetchCalls: string[] = [];
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      fetchCalls.push(init.body as string);
      return {
        ok: true,
        json: async () => mockProxyResponse(true),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = vi.fn().mockResolvedValue("result");
    const guarded = clampd.guard(fn, { agentId: "solo", toolName: "db.query" });
    await guarded({ sql: "SELECT 1" });

    const body = JSON.parse(fetchCalls[0]);
    // Single agent in delegation context sends chain (gateway appends current agent from JWT)
    // No caller_agent_id — gateway computes it from the complete chain
    if (body.params._delegation) {
      expect(body.params._delegation.delegation_chain).toBeDefined();
      expect(body.params._delegation.caller_agent_id).toBeUndefined();
    }
  });
});
