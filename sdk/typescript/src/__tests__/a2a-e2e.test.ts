/**
 * A2A Delegation E2E test - runs against live Clampd services.
 *
 * Simulates two agents in the same process where Agent A delegates to Agent B.
 *
 * Usage:
 *   # Start services:  cd clampd && docker compose up -d
 *   # Run:
 *   CLAMPD_E2E=1 npx vitest run src/__tests__/a2a-e2e.test.ts
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  withDelegation,
  getDelegation,
  hasCycle,
  delegationHeaders,
} from "../delegation";
import { ClampdClient } from "../client";

const GATEWAY_URL = process.env.CLAMPD_GATEWAY_URL || "http://localhost:8080";
const API_KEY = process.env.CLAMPD_API_KEY || "ag_test_demo_clampd_2026";
const AGENT_A = "b0000000-0000-0000-0000-000000000001";
const AGENT_B = "b0000000-0000-0000-0000-000000000002";

const SKIP = !process.env.CLAMPD_E2E;

function makeClient(agentId: string): ClampdClient {
  return new ClampdClient({
    gatewayUrl: GATEWAY_URL,
    agentId,
    apiKey: API_KEY,
  });
}

describe.skipIf(SKIP)("A2A Delegation E2E", () => {
  beforeAll(async () => {
    // Verify gateway is reachable
    const resp = await fetch(`${GATEWAY_URL}/health`);
    expect(resp.ok).toBe(true);
    console.log("Gateway healthy");
  });

  it("single agent proxy call works", async () => {
    const client = makeClient(AGENT_A);
    const resp = await client.proxy("db.query", {
      sql: "SELECT name FROM users WHERE id = 1",
    });
    console.log(`  Single agent: allowed=${resp.allowed}, risk=${resp.riskScore}`);
    expect(resp.allowed || resp.riskScore < 0.85).toBe(true);
  });

  it("no delegation context outside withDelegation", () => {
    const ctx = getDelegation();
    expect(ctx).toBeUndefined();
  });

  it("nested delegation auto-detected (A -> B)", async () => {
    await withDelegation(AGENT_A, async () => {
      const ctxA = getDelegation();
      expect(ctxA).toBeDefined();
      expect(ctxA!.chain).toEqual([AGENT_A]);
      console.log(`  Agent A: chain=${JSON.stringify(ctxA!.chain)}`);

      await withDelegation(AGENT_B, async () => {
        const ctxB = getDelegation();
        expect(ctxB).toBeDefined();
        expect(ctxB!.chain).toEqual([AGENT_A, AGENT_B]);
        expect(ctxB!.traceId).toBe(ctxA!.traceId); // same trace
        console.log(`  Agent B: chain=${JSON.stringify(ctxB!.chain)}, trace=${ctxB!.traceId}`);

        // Make a proxy call from Agent B (with delegation context)
        const client = makeClient(AGENT_B);
        const resp = await client.proxy("db.query", {
          sql: "SELECT COUNT(*) FROM orders",
        });
        console.log(`  Delegated: allowed=${resp.allowed}, risk=${resp.riskScore}`);
      });

      // Back to A
      const restored = getDelegation();
      expect(restored!.chain).toEqual([AGENT_A]);
    });

    // Outside all scopes
    expect(getDelegation()).toBeUndefined();
  });

  it("cycle detection: A -> B -> A", async () => {
    await withDelegation(AGENT_A, async () => {
      await withDelegation(AGENT_B, async () => {
        // A -> B -> A is a cycle
        expect(hasCycle([AGENT_A, AGENT_B, AGENT_A])).toBe(true);
        console.log("  Cycle detected: A -> B -> A");
      });
    });
  });

  it("delegation headers set correctly", async () => {
    await withDelegation(AGENT_A, async () => {
      await withDelegation(AGENT_B, async () => {
        const headers = delegationHeaders();
        expect(headers["X-Clampd-Delegation-Trace"]).toBeTruthy();
        expect(headers["X-Clampd-Delegation-Chain"]).toContain(AGENT_A);
        expect(headers["X-Clampd-Delegation-Chain"]).toContain(AGENT_B);
        expect(headers["X-Clampd-Delegation-Confidence"]).toBe("verified");
        console.log(`  Headers: ${JSON.stringify(headers)}`);
      });
    });

    // Outside - empty
    const empty = delegationHeaders();
    expect(Object.keys(empty)).toHaveLength(0);
  });

  it("concurrent delegations are isolated", async () => {
    const results: Record<string, string[]> = {};

    await Promise.all([
      withDelegation("agent-async-A", async () => {
        await new Promise((r) => setTimeout(r, 20));
        results.A = getDelegation()?.chain || [];
      }),
      withDelegation("agent-async-B", async () => {
        await new Promise((r) => setTimeout(r, 20));
        results.B = getDelegation()?.chain || [];
      }),
    ]);

    expect(results.A).toEqual(["agent-async-A"]);
    expect(results.B).toEqual(["agent-async-B"]);
    console.log(`  Async A: ${JSON.stringify(results.A)}, B: ${JSON.stringify(results.B)}`);
  });
});
