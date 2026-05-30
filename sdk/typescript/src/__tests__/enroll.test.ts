/**
 * Tests for the Ed25519 enrollment + re-key (rebind) flow.
 *
 * Runs the REAL enroll module (not the global mock in setup.ts) against a
 * temp CLAMPD_HOME and a stubbed fetch, so the rebind branch is covered.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// CLAMPD_HOME is read at module load, so set it before importing enroll.
const HOME = mkdtempSync(join(tmpdir(), "clampd-enroll-"));
process.env.CLAMPD_HOME = HOME;
vi.unmock("../enroll.js");
const { enroll } = await import("../enroll.js");

function fetchReturning(agentId: string) {
  return vi.fn(async () => ({
    status: 200,
    json: async () => ({ agent_id: agentId }),
    text: async () => "",
  })) as unknown as typeof fetch;
}

describe("enroll / re-key", () => {
  const ORIG_FETCH = globalThis.fetch;
  beforeEach(() => {
    delete process.env.CLAMPD_ENROLL_TOKEN;
    delete process.env.CLAMPD_REBIND_TOKEN;
  });
  afterEach(() => {
    globalThis.fetch = ORIG_FETCH;
    vi.restoreAllMocks();
  });

  it("CLAMPD_REBIND_TOKEN forces a re-key with a fresh key and rekey_token attestation", async () => {
    // 1. Normal enroll → caches identity for name "svc-ts".
    const f1 = fetchReturning("44444444-4444-4444-4444-444444444444");
    globalThis.fetch = f1;
    const first = await enroll("https://gw.clampd.dev", "ag_live_x", "svc-ts");
    const firstKey = first.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    expect(first.agentId).toBe("44444444-4444-4444-4444-444444444444");

    // 2. Re-key: rebind token forces a fresh keypair, same agent_id.
    process.env.CLAMPD_REBIND_TOKEN = "crt-xyz";
    let sentBody: Record<string, unknown> = {};
    globalThis.fetch = vi.fn(async (_url: unknown, init: { body?: string } = {}) => {
      sentBody = JSON.parse(init.body ?? "{}");
      return { status: 200, json: async () => ({ agent_id: "44444444-4444-4444-4444-444444444444" }), text: async () => "" };
    }) as unknown as typeof fetch;

    const rekeyed = await enroll("https://gw.clampd.dev", "ag_live_x", "svc-ts");
    const rekeyedKey = rekeyed.privateKey.export({ type: "pkcs8", format: "pem" }) as string;

    expect(sentBody.attestation_type).toBe("rekey_token");
    expect(sentBody.attestation).toBe("crt-xyz");
    expect(rekeyedKey).not.toBe(firstKey); // fresh keypair
    expect(rekeyed.agentId).toBe("44444444-4444-4444-4444-444444444444"); // same identity
  });
});
