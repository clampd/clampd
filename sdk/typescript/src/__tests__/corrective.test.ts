import { describe, it, expect } from "vitest";
import {
  parseCorrectiveAction,
  parseStructuredDenial,
  renderCorrectiveForLLM,
  syntheticDenial,
  type CorrectiveAction,
  type CorrectiveActionVariant,
  type StructuredDenial,
} from "../corrective.js";
import { ClampdBlockedError } from "../index.js";
import type { ProxyResponse } from "../client.js";

// ── Wire parsing: one test per variant ──────────────────────────────

/** Build a corrective in the gateway's actual wire shape — flat `kind`
 *  + `payload`. Matches `ag_common::denial::CorrectiveActionJson` and the
 *  dashboard `CorrectiveAction` TypeScript interface. */
function wireCorrective(actionKey: string, value: Record<string, unknown>) {
  return {
    kind: actionKey,
    payload: value,
    human_explanation: "test hint",
    confidence: "high",
    source: "rule",
  };
}

describe("parseCorrectiveAction — 8 variants", () => {
  it("parses switch_tool", () => {
    const c = parseCorrectiveAction(
      wireCorrective("switch_tool", { tool: "archive_table", scope: "db:write:soft_delete" }),
    );
    expect(c?.action).toMatchObject({
      kind: "switchTool",
      tool: "archive_table",
      scope: "db:write:soft_delete",
    });
  });

  it("parses downscope_to", () => {
    const c = parseCorrectiveAction(
      wireCorrective("downscope_to", { scope: "db:read:select" }),
    );
    expect(c?.action).toMatchObject({ kind: "downscopeTo", scope: "db:read:select" });
  });

  it("parses rename_field with camelCase 'from' (despite reserved-word wire key)", () => {
    const c = parseCorrectiveAction(
      wireCorrective("rename_field", { from: "uid", to: "user_id" }),
    );
    expect(c?.action).toMatchObject({ kind: "renameField", from: "uid", to: "user_id" });
  });

  it("parses redact_value (json_path → jsonPath)", () => {
    const c = parseCorrectiveAction(
      wireCorrective("redact_value", { json_path: "$.body", mask: "<X>" }),
    );
    expect(c?.action).toMatchObject({
      kind: "redactValue",
      jsonPath: "$.body",
      mask: "<X>",
    });
  });

  it("parses split_request", () => {
    const c = parseCorrectiveAction(
      wireCorrective("split_request", { max_items_per_batch: 100, current_items: 750 }),
    );
    expect(c?.action).toMatchObject({
      kind: "splitRequest",
      maxItemsPerBatch: 100,
      currentItems: 750,
    });
  });

  it("parses wait_and_retry with window_label", () => {
    const c = parseCorrectiveAction(
      wireCorrective("wait_and_retry", { retry_after_seconds: 60, window_label: "09:00-17:00 UTC" }),
    );
    expect(c?.action).toMatchObject({
      kind: "waitAndRetry",
      retryAfterSeconds: 60,
      windowLabel: "09:00-17:00 UTC",
    });
  });

  it("parses switch_endpoint (from_url/to_url → camelCase)", () => {
    const c = parseCorrectiveAction(
      wireCorrective("switch_endpoint", { from_url: "https://x", to_url: "https://approved/*" }),
    );
    expect(c?.action).toMatchObject({
      kind: "switchEndpoint",
      fromUrl: "https://x",
      toUrl: "https://approved/*",
    });
  });

  it("parses no_correction", () => {
    const c = parseCorrectiveAction(wireCorrective("no_correction", {}));
    expect(c?.action).toMatchObject({ kind: "noCorrection" });
  });

  it("returns null for missing input or unknown variant", () => {
    expect(parseCorrectiveAction(null)).toBeNull();
    expect(parseCorrectiveAction({})).toBeNull();
    // Unknown kind in the flat shape — parser drops gracefully.
    expect(
      parseCorrectiveAction({ kind: "teleport", payload: {} }),
    ).toBeNull();
  });

  it("defaults confidence=medium when missing or invalid", () => {
    const c = parseCorrectiveAction({
      kind: "no_correction",
      payload: {},
      confidence: "bogus",
      human_explanation: "x",
    });
    expect(c?.confidence).toBe("medium");
  });

  it("reads the rendered.{tool_result, short_label} block when present", () => {
    const c = parseCorrectiveAction({
      kind: "switch_tool",
      payload: { tool: "archive_table" },
      human_explanation: "Use archive_table",
      confidence: "high",
      source: "rule",
      rendered: {
        tool_result:
          "Denied: Use archive_table\nTry the `archive_table` tool instead.",
        short_label: "Switch tool",
      },
    });
    expect(c?.rendered).not.toBeNull();
    expect(c?.rendered?.toolResult).toContain("archive_table");
    expect(c?.rendered?.shortLabel).toBe("Switch tool");
  });

  it("leaves rendered=null when the gateway didn't ship the block (pre-0.23.1)", () => {
    const c = parseCorrectiveAction(wireCorrective("no_correction", {}));
    expect(c?.rendered).toBeNull();
  });

  it("renderCorrectiveForLLM prefers gateway-rendered string over client templates", () => {
    const c = parseCorrectiveAction({
      kind: "switch_tool",
      payload: { tool: "archive_table" },
      human_explanation: "ignored when rendered is present",
      confidence: "high",
      source: "rule",
      rendered: {
        tool_result: "TOOL_RESULT_FROM_GATEWAY",
        short_label: "Switch tool",
      },
    });
    expect(renderCorrectiveForLLM(c)).toBe("TOOL_RESULT_FROM_GATEWAY");
  });
});

// ── StructuredDenial parsing ────────────────────────────────────────

describe("parseStructuredDenial", () => {
  it("round-trips the full shape", () => {
    const raw = {
      rule_id: "R001",
      violated_predicate: "params.query MATCHES /DROP/i",
      offending_value: "DROP TABLE users",
      corrective: wireCorrective("switch_tool", { tool: "archive_table" }),
      reason_codes: ["HARD_DENY_MALICIOUS"],
      boundary_violation: null,
      boundary_matched_rule: null,
      idempotency_key: "abc-123",
    };
    const d = parseStructuredDenial(raw);
    expect(d).not.toBeNull();
    expect(d?.ruleId).toBe("R001");
    expect(d?.violatedPredicate).toBe("params.query MATCHES /DROP/i");
    expect(d?.idempotencyKey).toBe("abc-123");
    expect(d?.reasonCodes).toEqual(["HARD_DENY_MALICIOUS"]);
    expect(d?.corrective?.action.kind).toBe("switchTool");
  });

  it("returns null for null / empty input", () => {
    expect(parseStructuredDenial(null)).toBeNull();
    expect(parseStructuredDenial({})).toBeNull();
  });

  it("tolerates missing optional fields", () => {
    const d = parseStructuredDenial({ rule_id: "R002", violated_predicate: "foo" });
    expect(d).not.toBeNull();
    expect(d?.corrective).toBeNull();
    expect(d?.boundaryViolation).toBeNull();
    expect(d?.reasonCodes).toEqual([]);
  });
});

// ── Render templates ────────────────────────────────────────────────

function ca(action: CorrectiveActionVariant, opts: Partial<CorrectiveAction> = {}): CorrectiveAction {
  return {
    action,
    humanExplanation: opts.humanExplanation ?? "explanation here",
    confidence: opts.confidence ?? "high",
    source: opts.source ?? "rule",
    // Default: simulate a pre-0.23.1 gateway (no rendered block).
    // Tests that need to exercise the new gateway-rendered path set
    // this explicitly via opts.
    rendered: opts.rendered ?? null,
  };
}

describe("renderCorrectiveForLLM", () => {
  it("renders switchTool", () => {
    const out = renderCorrectiveForLLM(ca({ kind: "switchTool", tool: "archive_table" }));
    expect(out).toContain("archive_table");
    expect(out).toContain("Try the");
  });

  it("renders downscopeTo", () => {
    const out = renderCorrectiveForLLM(ca({ kind: "downscopeTo", scope: "db:read:select" }));
    expect(out).toContain("db:read:select");
    expect(out).toContain("Retry under scope");
  });

  it("renders renameField", () => {
    const out = renderCorrectiveForLLM(ca({ kind: "renameField", from: "uid", to: "user_id" }));
    expect(out).toContain("uid");
    expect(out).toContain("user_id");
  });

  it("renders redactValue", () => {
    const out = renderCorrectiveForLLM(ca({ kind: "redactValue", jsonPath: "$.body", mask: "<X>" }));
    expect(out).toContain("$.body");
  });

  it("renders splitRequest", () => {
    const out = renderCorrectiveForLLM(
      ca({ kind: "splitRequest", maxItemsPerBatch: 100, currentItems: 750 }),
    );
    expect(out).toContain("100");
  });

  it("renders waitAndRetry with window label", () => {
    const out = renderCorrectiveForLLM(
      ca({ kind: "waitAndRetry", retryAfterSeconds: 60, windowLabel: "09:00-17:00 UTC" }),
    );
    expect(out).toContain("60s");
    expect(out).toContain("09:00-17:00 UTC");
  });

  it("renders waitAndRetry without window label", () => {
    const out = renderCorrectiveForLLM(ca({ kind: "waitAndRetry", retryAfterSeconds: 30 }));
    expect(out).toContain("30s");
  });

  it("renders switchEndpoint", () => {
    const out = renderCorrectiveForLLM(
      ca({ kind: "switchEndpoint", fromUrl: "https://x", toUrl: "https://approved" }),
    );
    expect(out).toContain("https://approved");
    expect(out).toContain("https://x");
  });

  it("renders noCorrection with explanation only", () => {
    const out = renderCorrectiveForLLM(
      ca({ kind: "noCorrection" }, { humanExplanation: "No path forward" }),
    );
    expect(out).toContain("No path forward");
  });

  it("returns empty string for low confidence (dashboard-only)", () => {
    const out = renderCorrectiveForLLM(
      ca({ kind: "switchTool", tool: "x" }, { confidence: "low" }),
    );
    expect(out).toBe("");
  });

  it("returns empty string for null input", () => {
    expect(renderCorrectiveForLLM(null)).toBe("");
  });
});

// ── ClampdBlockedError integration ──────────────────────────────────

describe("ClampdBlockedError — typed denial + toToolResult", () => {
  it("exposes the typed denial when present and renders the corrective", () => {
    const denial: StructuredDenial = {
      ruleId: "R001",
      violatedPredicate: "DROP detected",
      offendingValue: "",
      corrective: {
        action: { kind: "switchTool", tool: "archive_table" },
        humanExplanation: "Use archive_table",
        confidence: "high",
        source: "rule",
        rendered: null,
      },
      reasonCodes: [],
      boundaryViolation: null,
      boundaryMatchedRule: null,
      idempotencyKey: null,
    };
    const resp: ProxyResponse = {
      request_id: "req_test",
      allowed: false,
      risk_score: 0.95,
      denial,
      matched_rules: ["R001"],
      latency_ms: 10,
      degraded_stages: [],
      session_flags: [],
    };
    const err = new ClampdBlockedError(resp);
    expect(err.denial).toBe(denial);
    expect(err.message).toContain("Use archive_table");
    expect(err.toToolResult()).toContain("archive_table");
    expect(err.toToolResult()).toContain("Try the");
  });

  it("falls back to legacy denial_reason when typed denial is absent", () => {
    const resp: ProxyResponse = {
      request_id: "req_test",
      allowed: false,
      risk_score: 1.0,
      denial: null,
      denial_reason: "gateway_timeout",
      matched_rules: [],
      latency_ms: 0,
      degraded_stages: [],
      session_flags: [],
    };
    const err = new ClampdBlockedError(resp);
    expect(err.denial.ruleId).toBe("SDK/synthetic");
    expect(err.denial.violatedPredicate).toBe("gateway_timeout");
    expect(err.message).toContain("gateway_timeout");
  });

  it("toToolResult falls back to violatedPredicate when no corrective", () => {
    const resp: ProxyResponse = {
      request_id: "req_test",
      allowed: false,
      risk_score: 1.0,
      denial: {
        ruleId: "R-FOO",
        violatedPredicate: "reason text",
        offendingValue: "",
        corrective: null,
        reasonCodes: [],
        boundaryViolation: null,
        boundaryMatchedRule: null,
        idempotencyKey: null,
      },
      matched_rules: [],
      latency_ms: 0,
      degraded_stages: [],
      session_flags: [],
    };
    const err = new ClampdBlockedError(resp);
    expect(err.toToolResult()).toContain("reason text");
  });

  it("suppresses low-confidence corrective from toToolResult (falls back)", () => {
    const resp: ProxyResponse = {
      request_id: "req_test",
      allowed: false,
      risk_score: 1.0,
      denial: {
        ruleId: "R-LOW",
        violatedPredicate: "silent",
        offendingValue: "",
        corrective: {
          action: { kind: "switchTool", tool: "x" },
          humanExplanation: "quiet",
          confidence: "low",
          source: "rule",
          rendered: null,
        },
        reasonCodes: [],
        boundaryViolation: null,
        boundaryMatchedRule: null,
        idempotencyKey: null,
      },
      matched_rules: [],
      latency_ms: 0,
      degraded_stages: [],
      session_flags: [],
    };
    const err = new ClampdBlockedError(resp);
    // Low-confidence corrective is suppressed; the rendered output should
    // NOT mention the tool but should still produce a fallback string.
    const rendered = err.toToolResult();
    expect(rendered.length).toBeGreaterThan(0);
    expect(rendered).not.toContain("`x`");
  });
});

// ── syntheticDenial helper ──────────────────────────────────────────

describe("syntheticDenial", () => {
  it("builds a typed denial for SDK-side synthetic errors", () => {
    const d = syntheticDenial("SDK/timeout", "gateway_timeout");
    expect(d.ruleId).toBe("SDK/timeout");
    expect(d.violatedPredicate).toBe("gateway_timeout");
    expect(d.corrective).toBeNull();
  });
});

// ── Loop detection (idempotency_key) ─────────────────────────────────

import { ClampdClient } from "../client.js";
import { ClampdLoopError } from "../interceptor.js";

describe("Loop detection — recordAndCheckLoop", () => {
  function makeResp(idempotencyKey: string | null): ProxyResponse {
    return {
      request_id: "x",
      allowed: false,
      risk_score: 1.0,
      denial: {
        ruleId: "R001",
        violatedPredicate: "x",
        offendingValue: "",
        corrective: null,
        reasonCodes: [],
        boundaryViolation: null,
        boundaryMatchedRule: null,
        idempotencyKey,
      },
      matched_rules: [],
      latency_ms: 0,
      degraded_stages: [],
      session_flags: [],
    };
  }

  const SECRET = "test-secret-32-chars-for-jwt-signing!";

  it("first denial with an idempotency_key is not a loop", () => {
    const c = new ClampdClient({ agentId: "a", secret: SECRET });
    expect(c.recordAndCheckLoop(makeResp("abc123"))).toBe(false);
  });

  it("second denial with the same key is detected as a loop", () => {
    const c = new ClampdClient({ agentId: "a", secret: SECRET });
    c.recordAndCheckLoop(makeResp("abc123"));
    expect(c.recordAndCheckLoop(makeResp("abc123"))).toBe(true);
  });

  it("different keys do not trip detection", () => {
    const c = new ClampdClient({ agentId: "a", secret: SECRET });
    expect(c.recordAndCheckLoop(makeResp("key1"))).toBe(false);
    expect(c.recordAndCheckLoop(makeResp("key2"))).toBe(false);
  });

  it("denials without an idempotency_key are never flagged", () => {
    const c = new ClampdClient({ agentId: "a", secret: SECRET });
    expect(c.recordAndCheckLoop(makeResp(null))).toBe(false);
    expect(c.recordAndCheckLoop(makeResp(null))).toBe(false);
  });
});

describe("ClampdLoopError", () => {
  it("is a subclass of ClampdBlockedError so existing catches propagate it", () => {
    // Build one and check instanceof both classes.
    const resp: ProxyResponse = {
      request_id: "x",
      allowed: false,
      risk_score: 1.0,
      denial: {
        ruleId: "R001",
        violatedPredicate: "x",
        offendingValue: "",
        corrective: null,
        reasonCodes: [],
        boundaryViolation: null,
        boundaryMatchedRule: null,
        idempotencyKey: "abc",
      },
      matched_rules: [],
      latency_ms: 0,
      degraded_stages: [],
      session_flags: [],
    };
    const err = new ClampdLoopError(resp);
    expect(err).toBeInstanceOf(ClampdBlockedError);
    expect(err).toBeInstanceOf(ClampdLoopError);
  });

  it("carries the typed denial and a loop-specific message", () => {
    const resp: ProxyResponse = {
      request_id: "x",
      allowed: false,
      risk_score: 1.0,
      denial: {
        ruleId: "R001",
        violatedPredicate: "x",
        offendingValue: "",
        corrective: null,
        reasonCodes: [],
        boundaryViolation: null,
        boundaryMatchedRule: null,
        idempotencyKey: "abc123",
      },
      matched_rules: [],
      latency_ms: 0,
      degraded_stages: [],
      session_flags: [],
    };
    const err = new ClampdLoopError(resp);
    expect(err.name).toBe("ClampdLoopError");
    expect(err.message).toContain("loop");
    expect(err.message).toContain("abc123");
    expect(err.denial.idempotencyKey).toBe("abc123");
    expect(err.isLoop()).toBe(true);
  });
});
