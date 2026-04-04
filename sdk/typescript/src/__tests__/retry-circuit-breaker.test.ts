import { describe, it, expect, vi, beforeEach } from "vitest";
import { ClampdClient } from "../client.js";

process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

describe("retry", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("retries on network error up to maxRetries", async () => {
    let attempts = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => {
      attempts++;
      if (attempts < 3) throw new Error("ECONNREFUSED");
      return {
        ok: true,
        json: async () => ({
          request_id: "req-ok",
          allowed: true,
          risk_score: 0.1,
          latency_ms: 5,
          degraded_stages: [],
          session_flags: [],
        }),
      };
    }));

    const client = new ClampdClient({
      agentId: "test",
      retry: { maxRetries: 3, baseDelayMs: 10 },
    });

    const res = await client.proxy("test.tool", { key: "value" });
    expect(res.allowed).toBe(true);
    expect(attempts).toBe(3);
  });

  it("returns blocked response after all retries exhausted", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));

    const client = new ClampdClient({
      agentId: "test",
      retry: { maxRetries: 2, baseDelayMs: 10 },
    });

    const res = await client.proxy("test.tool", {});
    expect(res.allowed).toBe(false);
    expect(res.denial_reason).toContain("ECONNREFUSED");
  });

  it("does not retry on 4xx client errors (except 429)", async () => {
    let attempts = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => {
      attempts++;
      return {
        ok: false,
        status: 400,
        text: async () => "Bad Request",
      };
    }));

    const client = new ClampdClient({
      agentId: "test",
      retry: { maxRetries: 3, baseDelayMs: 10 },
    });

    const res = await client.proxy("test.tool", {});
    expect(res.allowed).toBe(false);
    expect(attempts).toBe(1); // No retries on 400
  });

  it("retries on 429 rate limit", async () => {
    let attempts = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => {
      attempts++;
      if (attempts < 2) {
        return { ok: false, status: 429, text: async () => "Rate limited" };
      }
      return {
        ok: true,
        json: async () => ({
          request_id: "req-ok",
          allowed: true,
          risk_score: 0.1,
          latency_ms: 5,
          degraded_stages: [],
          session_flags: [],
        }),
      };
    }));

    const client = new ClampdClient({
      agentId: "test",
      retry: { maxRetries: 2, baseDelayMs: 10 },
    });

    const res = await client.proxy("test.tool", {});
    expect(res.allowed).toBe(true);
    expect(attempts).toBe(2);
  });

  it("retries on 5xx server errors", async () => {
    let attempts = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => {
      attempts++;
      if (attempts < 3) {
        return { ok: false, status: 502, text: async () => "Bad Gateway" };
      }
      return {
        ok: true,
        json: async () => ({
          request_id: "req-ok",
          allowed: true,
          risk_score: 0.05,
          latency_ms: 4,
          degraded_stages: [],
          session_flags: [],
        }),
      };
    }));

    const client = new ClampdClient({
      agentId: "test",
      retry: { maxRetries: 3, baseDelayMs: 10 },
    });

    const res = await client.proxy("test.tool", {});
    expect(res.allowed).toBe(true);
    expect(attempts).toBe(3);
  });
});

describe("circuit breaker", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("opens circuit after threshold failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));

    const client = new ClampdClient({
      agentId: "test",
      circuitBreaker: { threshold: 3, resetTimeoutMs: 60_000 },
    });

    // 3 failures to open the circuit
    await client.proxy("t", {});
    await client.proxy("t", {});
    await client.proxy("t", {});

    // 4th call should be short-circuited (no fetch)
    const mockFetch = vi.fn().mockRejectedValue(new Error("should not be called"));
    vi.stubGlobal("fetch", mockFetch);

    const res = await client.proxy("t", {});
    expect(res.allowed).toBe(false);
    expect(res.denial_reason).toContain("Circuit breaker open");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("allows probe request after resetTimeout (half-open)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));

    const client = new ClampdClient({
      agentId: "test",
      circuitBreaker: { threshold: 2, resetTimeoutMs: 50 },
    });

    // Open the circuit
    await client.proxy("t", {});
    await client.proxy("t", {});

    // Wait for reset timeout
    await new Promise((r) => setTimeout(r, 60));

    // Should allow a probe request now
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        request_id: "req-ok",
        allowed: true,
        risk_score: 0.05,
        latency_ms: 3,
        degraded_stages: [],
        session_flags: [],
      }),
    }));

    const res = await client.proxy("t", {});
    expect(res.allowed).toBe(true);
  });

  it("closes circuit on successful probe", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));

    const client = new ClampdClient({
      agentId: "test",
      circuitBreaker: { threshold: 2, resetTimeoutMs: 50 },
    });

    // Open the circuit
    await client.proxy("t", {});
    await client.proxy("t", {});

    await new Promise((r) => setTimeout(r, 60));

    // Successful probe
    const successFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        request_id: "req-ok",
        allowed: true,
        risk_score: 0.05,
        latency_ms: 3,
        degraded_stages: [],
        session_flags: [],
      }),
    });
    vi.stubGlobal("fetch", successFetch);

    await client.proxy("t", {});

    // Circuit should be closed now — subsequent calls go through
    const res = await client.proxy("t", {});
    expect(res.allowed).toBe(true);
    expect(successFetch).toHaveBeenCalledTimes(2);
  });

  it("resets failure count on success", async () => {
    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 2) {
        return {
          ok: true,
          json: async () => ({
            request_id: "req-ok",
            allowed: true,
            risk_score: 0.05,
            latency_ms: 3,
            degraded_stages: [],
            session_flags: [],
          }),
        };
      }
      throw new Error("down");
    }));

    const client = new ClampdClient({
      agentId: "test",
      circuitBreaker: { threshold: 3, resetTimeoutMs: 60_000 },
    });

    // 1 failure, then 1 success (resets counter), then 2 more failures
    await client.proxy("t", {}); // fail (count=1)
    await client.proxy("t", {}); // success (count=0)

    // Now 2 more failures should NOT open circuit (threshold=3)
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    await client.proxy("t", {}); // fail (count=1)
    await client.proxy("t", {}); // fail (count=2)

    // Should still allow requests (not open yet)
    const probeResult = await client.proxy("t", {}); // fail (count=3, now open)
    // This 5th call triggers the circuit
    const blockedResult = await client.proxy("t", {});
    expect(blockedResult.denial_reason).toContain("Circuit breaker open");
  });
});
