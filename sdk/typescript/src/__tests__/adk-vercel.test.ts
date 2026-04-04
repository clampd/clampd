import { describe, it, expect, vi, beforeEach } from "vitest";
import clampd, { ClampdBlockedError } from "../index.js";

process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

function mockProxyResponse(allowed = true, denial_reason: string | null = null) {
  return {
    request_id: "req-test",
    allowed,
    risk_score: allowed ? 0.1 : 0.95,
    denial_reason,
    latency_ms: 5,
    degraded_stages: [],
    session_flags: [],
    scope_granted: allowed ? "db:read" : null,
    tool_response: allowed ? "ok" : null,
  };
}

// ── clampd.adk() ─────────────────────────────────────────────────

describe("clampd.adk()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("beforeTool returns null when proxy allows", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const { beforeTool } = clampd.adk({ agentId: "test" });
    const result = await beforeTool("db.query", { sql: "SELECT 1" });

    expect(result).toBeNull();
  });

  it("beforeTool returns { error } when proxy denies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false, "dangerous query"),
    }));

    const { beforeTool } = clampd.adk({ agentId: "test" });
    const result = await beforeTool("db.query", { sql: "DROP TABLE users" });

    expect(result).not.toBeNull();
    expect(result).toHaveProperty("error");
    expect(result!.error).toContain("dangerous query");
  });

  it("afterTool is returned only when checkResponse is true", () => {
    const withoutCheck = clampd.adk({ agentId: "test" });
    expect(withoutCheck.afterTool).toBeUndefined();

    const withCheck = clampd.adk({ agentId: "test", checkResponse: true });
    expect(withCheck.afterTool).toBeDefined();
    expect(typeof withCheck.afterTool).toBe("function");
  });

  it("afterTool calls inspect endpoint", async () => {
    const mockFetch = vi.fn()
      // First call: beforeTool proxy
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockProxyResponse(true),
      })
      // Second call: afterTool inspect
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockProxyResponse(true),
      });
    vi.stubGlobal("fetch", mockFetch);

    const { beforeTool, afterTool } = clampd.adk({ agentId: "test", checkResponse: true });

    await beforeTool("db.query", { sql: "SELECT 1" });
    const result = await afterTool!("db.query", { rows: [{ id: 1 }] });

    expect(result).toBeNull();
    expect(mockFetch).toHaveBeenCalledTimes(2);
    // The second fetch call should be to the inspect endpoint
    const secondCallUrl = mockFetch.mock.calls[1][0] as string;
    expect(secondCallUrl).toContain("/inspect");
  });

  it("failOpen: true returns null on non-ClampdBlockedError", async () => {
    // Simulate a generic error (not ClampdBlockedError) being thrown during proxy.
    // With failOpen: true, the catch block falls through and returns null.
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => {
      throw new TypeError("Cannot read properties of undefined");
    }));

    const { beforeTool } = clampd.adk({ agentId: "test", failOpen: true });
    const result = await beforeTool("db.query", { sql: "SELECT 1" });

    expect(result).toBeNull();
  });

  it("failOpen: false returns { error } on gateway error", async () => {
    // When fetch fails, ClampdClient returns a synthetic blocked response with allowed: false
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    const { beforeTool } = clampd.adk({ agentId: "test", failOpen: false });
    const result = await beforeTool("db.query", { sql: "SELECT 1" });

    expect(result).not.toBeNull();
    expect(result).toHaveProperty("error");
    expect(result!.error).toContain("Fetch error");
  });
});

// ── clampd.vercelAI() ───────────────────────────────────────────

describe("clampd.vercelAI()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("wraps tool execute and lets allowed calls through", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const originalExecute = vi.fn().mockResolvedValue({ rows: [{ id: 1 }] });
    const toolDefs = {
      dbQuery: {
        description: "Query the database",
        parameters: { type: "object", properties: { sql: { type: "string" } } },
        execute: originalExecute,
      },
    };

    const wrapped = clampd.vercelAI(toolDefs, { agentId: "test" });
    const result = await wrapped.dbQuery.execute!({ sql: "SELECT 1" });

    expect(result).toEqual({ rows: [{ id: 1 }] });
    expect(originalExecute).toHaveBeenCalledOnce();
  });

  it("throws ClampdBlockedError when proxy denies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false, "blocked"),
    }));

    const toolDefs = {
      dbQuery: {
        description: "Query the database",
        parameters: {},
        execute: vi.fn().mockResolvedValue("result"),
      },
    };

    const wrapped = clampd.vercelAI(toolDefs, { agentId: "test" });

    await expect(wrapped.dbQuery.execute!({ sql: "DROP TABLE" })).rejects.toThrow(ClampdBlockedError);
    expect(toolDefs.dbQuery.execute).not.toHaveBeenCalled();
  });

  it("passes through tools without execute functions", () => {
    vi.stubGlobal("fetch", vi.fn());

    const toolDefs = {
      noExec: {
        description: "A tool with no execute",
        parameters: { type: "object" },
      },
    };

    const wrapped = clampd.vercelAI(toolDefs, { agentId: "test" });

    expect(wrapped.noExec.description).toBe("A tool with no execute");
    expect(wrapped.noExec.execute).toBeUndefined();
  });

  it("preserves tool properties (description, parameters)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const params = { type: "object", properties: { sql: { type: "string" } } };
    const toolDefs = {
      dbQuery: {
        description: "Query the database",
        parameters: params,
        execute: vi.fn().mockResolvedValue("ok"),
      },
    };

    const wrapped = clampd.vercelAI(toolDefs, { agentId: "test" });

    expect(wrapped.dbQuery.description).toBe("Query the database");
    expect(wrapped.dbQuery.parameters).toBe(params);
    expect(typeof wrapped.dbQuery.execute).toBe("function");
  });

  it("sends correct tool name to proxy", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    });
    vi.stubGlobal("fetch", mockFetch);

    const toolDefs = {
      "my-special-tool": {
        description: "A special tool",
        parameters: {},
        execute: vi.fn().mockResolvedValue("done"),
      },
    };

    const wrapped = clampd.vercelAI(toolDefs, { agentId: "test" });
    await wrapped["my-special-tool"].execute!({ input: "test" });

    // The fetch call body should contain the tool name
    const fetchBody = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    expect(fetchBody.tool).toBe("my-special-tool");
  });
});
