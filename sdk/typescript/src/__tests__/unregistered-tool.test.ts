import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ClampdUnregisteredToolError, ClampdBlockedError } from "../index.js";
import { raiseIfUnregistered, _registeredDescriptors } from "../_frameworkAdapters.js";
import type { ProxyResponse } from "../client.js";

// Tests signing — matches the pattern in the other SDK tests.
process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

// ── Helpers ─────────────────────────────────────────────────────────

function deniedResponse(denialReason: string): ProxyResponse {
  return {
    request_id: "req-denied",
    allowed: false,
    risk_score: 0.95,
    denial_reason: denialReason,
    matched_rules: [],
    latency_ms: 3,
    degraded_stages: [],
    session_flags: [],
  };
}

function allowedResponse(): ProxyResponse {
  return {
    request_id: "req-ok",
    allowed: true,
    risk_score: 0.05,
    denial_reason: null,
    matched_rules: [],
    latency_ms: 4,
    degraded_stages: [],
    session_flags: [],
    scope_granted: "db:query:read",
    tool_response: "ok",
  };
}

// ── raiseIfUnregistered ─────────────────────────────────────────────

describe("raiseIfUnregistered", () => {
  it("throws when denialReason starts with tool_not_registered:", () => {
    const resp = deniedResponse("tool_not_registered:my.tool");
    expect(() => raiseIfUnregistered("my.tool", resp)).toThrow(
      ClampdUnregisteredToolError,
    );
    try {
      raiseIfUnregistered("my.tool", resp);
    } catch (e) {
      expect(e).toBeInstanceOf(ClampdUnregisteredToolError);
      expect((e as ClampdUnregisteredToolError).toolName).toBe("my.tool");
    }
  });

  it("throws when denialReason starts with tool_not_classified:", () => {
    const resp = deniedResponse("tool_not_classified:my.other_tool");
    expect(() => raiseIfUnregistered("my.other_tool", resp)).toThrow(
      ClampdUnregisteredToolError,
    );
  });

  it("does not throw for other denial reasons", () => {
    const resp = deniedResponse("Policy denied: scope mismatch");
    expect(() => raiseIfUnregistered("my.tool", resp)).not.toThrow();
  });

  it("does not throw on allowed proxy responses", () => {
    expect(() => raiseIfUnregistered("my.tool", allowedResponse())).not.toThrow();
  });

  it("does not throw when response is undefined", () => {
    expect(() => raiseIfUnregistered("my.tool", undefined)).not.toThrow();
  });
});

// ── ClampdUnregisteredToolError class shape ─────────────────────────

describe("ClampdUnregisteredToolError", () => {
  it("is not an instance of ClampdBlockedError", () => {
    const err = new ClampdUnregisteredToolError("x");
    expect(err instanceof ClampdBlockedError).toBe(false);
    // sanity: it IS an Error and an instance of itself
    expect(err instanceof Error).toBe(true);
    expect(err instanceof ClampdUnregisteredToolError).toBe(true);
  });

  it("default hint message contains an actionable next step", () => {
    const err = new ClampdUnregisteredToolError("db.query");
    // Hint should mention registerTool() and the tool name so the
    // developer can copy-paste the fix into module-load code.
    expect(err.hint).toMatch(/registerTool/);
    expect(err.hint).toContain("db.query");
    expect(err.hint).toMatch(/category/);
    // Top-level message exposes the hint too.
    expect(err.message).toContain("db.query");
    expect(err.message).toContain(err.hint);
  });

  it("respects custom hint override", () => {
    const err = new ClampdUnregisteredToolError("db.query", {
      hint: "Custom hint here.",
    });
    expect(err.hint).toBe("Custom hint here.");
    expect(err.message).toContain("Custom hint here.");
  });
});

// ── Integration: langchain factory propagates the typed error ───────

describe("langchain integration — ClampdUnregisteredToolError propagation", () => {
  beforeEach(() => {
    _registeredDescriptors.clear();
  });
  afterEach(() => {
    _registeredDescriptors.clear();
  });

  it("ClampdUnregisteredToolError propagates out (not converted to ClampdBlockedError)", async () => {
    // Lazy import to avoid loading @langchain/core at suite boot.
    const { createClampdDatabaseTool } = await import("../langchain.js");

    // Mock client whose .proxy() resolves with a tool_not_registered:
    // denial — exactly the shape the gateway returns when the
    // descriptor is missing for that org.
    const mockClient = {
      agentId: "test-agent",
      proxy: vi.fn().mockResolvedValue(
        deniedResponse("tool_not_registered:database.query"),
      ),
    } as unknown as import("../client.js").ClampdClient;

    const tool = await createClampdDatabaseTool({ client: mockClient });

    // tool.invoke runs the langchain `func`, which calls client.proxy
    // and then raiseIfUnregistered — the unregistered error must bubble
    // out untouched.
    await expect(tool.invoke({ query: "SELECT 1" })).rejects.toThrow(
      ClampdUnregisteredToolError,
    );

    // And specifically: it is NOT a ClampdBlockedError. This is the
    // contract that lets callers catch the developer-error case
    // separately from generic policy denials.
    try {
      await tool.invoke({ query: "SELECT 1" });
    } catch (e) {
      expect(e).toBeInstanceOf(ClampdUnregisteredToolError);
      expect(e instanceof ClampdBlockedError).toBe(false);
    }

    expect(mockClient.proxy).toHaveBeenCalled();
  });
});
