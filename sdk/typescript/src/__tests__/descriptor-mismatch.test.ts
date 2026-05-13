import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  ClampdBlockedError,
  ClampdDescriptorMismatchError,
  ClampdUnregisteredToolError,
} from "../index.js";
import {
  raiseForDescriptorErrors,
  raiseIfUnregistered,
  _registeredDescriptors,
} from "../_frameworkAdapters.js";
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

// ── raiseForDescriptorErrors / raiseIfUnregistered ──────────────────

describe("raiseForDescriptorErrors", () => {
  it("throws ClampdDescriptorMismatchError on descriptor_hash_mismatch: prefix", () => {
    const resp = deniedResponse(
      "descriptor_hash_mismatch: tool 'mcp_postgres_query' was called with " +
        "hash 5587c5abcd1234ef but only a different hash is approved",
    );
    expect(() =>
      raiseForDescriptorErrors("mcp_postgres_query", resp),
    ).toThrow(ClampdDescriptorMismatchError);
    try {
      raiseForDescriptorErrors("mcp_postgres_query", resp);
    } catch (e) {
      expect(e).toBeInstanceOf(ClampdDescriptorMismatchError);
      expect((e as ClampdDescriptorMismatchError).toolName).toBe(
        "mcp_postgres_query",
      );
    }
  });

  it("extracts the attempted hash from the reason text", () => {
    const resp = deniedResponse(
      "descriptor_hash_mismatch: tool 'foo' was called with hash " +
        "deadbeefcafef00d1234 but only a different hash is approved",
    );
    try {
      raiseForDescriptorErrors("foo", resp);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ClampdDescriptorMismatchError);
      expect((e as ClampdDescriptorMismatchError).attemptedHash).toBe(
        "deadbeefcafef00d1234",
      );
    }
  });

  it("attemptedHash is undefined when reason lacks the hash fragment", () => {
    const resp = deniedResponse(
      "descriptor_hash_mismatch: details elided",
    );
    try {
      raiseForDescriptorErrors("foo", resp);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ClampdDescriptorMismatchError);
      expect((e as ClampdDescriptorMismatchError).attemptedHash).toBeUndefined();
    }
  });

  it("does not throw for other denial reasons", () => {
    const resp = deniedResponse("Policy denied: scope mismatch");
    expect(() => raiseForDescriptorErrors("my.tool", resp)).not.toThrow();
  });

  it("does not throw on allowed proxy responses", () => {
    expect(() =>
      raiseForDescriptorErrors("my.tool", allowedResponse()),
    ).not.toThrow();
  });

  it("does not throw when response is undefined", () => {
    expect(() =>
      raiseForDescriptorErrors("my.tool", undefined),
    ).not.toThrow();
  });

  it("still throws ClampdUnregisteredToolError on tool_not_registered: prefix", () => {
    const resp = deniedResponse("tool_not_registered:my.tool");
    expect(() => raiseForDescriptorErrors("my.tool", resp)).toThrow(
      ClampdUnregisteredToolError,
    );
  });

  it("legacy raiseIfUnregistered alias also throws ClampdDescriptorMismatchError", () => {
    const resp = deniedResponse(
      "descriptor_hash_mismatch: tool 'foo' was called with hash abcd1234 " +
        "but only a different hash is approved",
    );
    expect(() => raiseIfUnregistered("foo", resp)).toThrow(
      ClampdDescriptorMismatchError,
    );
  });
});

// ── ClampdDescriptorMismatchError class shape ───────────────────────

describe("ClampdDescriptorMismatchError", () => {
  it("is not an instance of ClampdBlockedError", () => {
    const err = new ClampdDescriptorMismatchError("x");
    expect(err instanceof ClampdBlockedError).toBe(false);
    // sanity: it IS an Error and an instance of itself
    expect(err instanceof Error).toBe(true);
    expect(err instanceof ClampdDescriptorMismatchError).toBe(true);
  });

  it("is not an instance of ClampdUnregisteredToolError (sibling, not subclass)", () => {
    const err = new ClampdDescriptorMismatchError("x");
    expect(err instanceof ClampdUnregisteredToolError).toBe(false);

    // Converse direction too — the two typed errors are siblings.
    const unregistered = new ClampdUnregisteredToolError("x");
    expect(unregistered instanceof ClampdDescriptorMismatchError).toBe(false);
  });

  it("default hint contains a dashboard action and the truncated hash", () => {
    const err = new ClampdDescriptorMismatchError("db.query", {
      attemptedHash: "5587c5abcd1234ef0011223344556677",
    });
    expect(err.toolName).toBe("db.query");
    expect(err.attemptedHash).toBe("5587c5abcd1234ef0011223344556677");
    expect(err.hint.toLowerCase()).toContain("dashboard");
    expect(err.hint).toContain("db.query");
    // First 16 chars should be embedded for quick scanning.
    expect(err.hint).toContain("5587c5abcd1234ef");
    // Top-level message exposes the hint and the tool name.
    expect(err.message).toContain("db.query");
    expect(err.message).toContain("does not match");
    expect(err.message).toContain(err.hint);
  });

  it("default hint without hash still mentions the dashboard", () => {
    const err = new ClampdDescriptorMismatchError("db.query");
    expect(err.attemptedHash).toBeUndefined();
    expect(err.hint.toLowerCase()).toContain("dashboard");
    expect(err.hint).toContain("db.query");
  });

  it("respects custom hint override", () => {
    const err = new ClampdDescriptorMismatchError("db.query", {
      attemptedHash: "abc",
      hint: "Custom rotate-hash docs.",
    });
    expect(err.hint).toBe("Custom rotate-hash docs.");
    expect(err.message).toContain("Custom rotate-hash docs.");
  });
});

// ── Integration: langchain factory propagates the typed error ───────

describe("langchain integration — ClampdDescriptorMismatchError propagation", () => {
  beforeEach(() => {
    _registeredDescriptors.clear();
  });
  afterEach(() => {
    _registeredDescriptors.clear();
  });

  it("ClampdDescriptorMismatchError propagates out (not converted to ClampdBlockedError)", async () => {
    // Lazy import to avoid loading @langchain/core at suite boot.
    const { createClampdDatabaseTool } = await import("../langchain.js");

    // Mock client whose .proxy() resolves with a descriptor_hash_mismatch:
    // denial — exactly the shape the gateway returns when the descriptor
    // hash sent doesn't match any approved version for the org.
    const mockClient = {
      agentId: "test-agent",
      proxy: vi.fn().mockResolvedValue(
        deniedResponse(
          "descriptor_hash_mismatch: tool 'database.query' was called " +
            "with hash 5587c5abcd1234ef but only a different hash is approved",
        ),
      ),
    } as unknown as import("../client.js").ClampdClient;

    const tool = await createClampdDatabaseTool({ client: mockClient });

    await expect(tool.invoke({ query: "SELECT 1" })).rejects.toThrow(
      ClampdDescriptorMismatchError,
    );

    // And specifically: it is NOT a ClampdBlockedError.
    try {
      await tool.invoke({ query: "SELECT 1" });
    } catch (e) {
      expect(e).toBeInstanceOf(ClampdDescriptorMismatchError);
      expect(e instanceof ClampdBlockedError).toBe(false);
      expect((e as ClampdDescriptorMismatchError).attemptedHash).toBe(
        "5587c5abcd1234ef",
      );
    }

    expect(mockClient.proxy).toHaveBeenCalled();
  });
});
