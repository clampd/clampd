import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash, generateKeyPairSync, sign, createPublicKey, KeyObject } from "node:crypto";
import {
  verifyScopeToken,
  requireScope,
  getCurrentScopeToken,
  ScopeVerificationError,
  setScopeToken,
  type ScopeTokenClaims,
} from "../tool-verify.js";

// ── Ed25519 test keypair ─────────────────────────────────────────────

const { privateKey: TEST_PRIVATE_KEY, publicKey: TEST_PUBLIC_KEY } =
  generateKeyPairSync("ed25519");

function makeScopeToken(
  payload: Record<string, unknown>,
  privateKey: KeyObject = TEST_PRIVATE_KEY,
): string {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadJson).toString("base64url");
  const sig = sign(null, Buffer.from(payloadB64), privateKey);
  const sigB64 = sig.toString("base64url");
  return `${payloadB64}.${sigB64}`;
}

function validPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: "agent-123",
    scope: "data:pii:query exec:shell:run",
    tool: "db.query",
    binding: createHash("sha256").update('db.query|{"sql":"SELECT 1"}').digest("hex"),
    exp: now + 300,
    rid: "req-abc-123",
    ...overrides,
  };
}

describe("verifyScopeToken", () => {
  it("verifies a valid token with explicit public key", async () => {
    const token = makeScopeToken(validPayload());
    const claims = await verifyScopeToken(token, TEST_PUBLIC_KEY);

    expect(claims.sub).toBe("agent-123");
    expect(claims.tool).toBe("db.query");
    expect(claims.rid).toBe("req-abc-123");
    expect(claims.scope).toContain("data:pii:query");
  });

  it("rejects expired token", async () => {
    const payload = validPayload({ exp: Math.floor(Date.now() / 1000) - 60 });
    const token = makeScopeToken(payload);

    try {
      await verifyScopeToken(token, TEST_PUBLIC_KEY);
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ScopeVerificationError);
      const err = e as ScopeVerificationError;
      expect(err.reason).toBe("Token expired");
      expect(err.claims).toBeDefined();
      expect(err.claims!.sub).toBe("agent-123");
    }
  });

  it("rejects invalid signature (wrong key)", async () => {
    const { privateKey: otherPrivate } = generateKeyPairSync("ed25519");
    const token = makeScopeToken(validPayload(), otherPrivate);

    await expect(verifyScopeToken(token, TEST_PUBLIC_KEY)).rejects.toThrow(
      "Invalid signature",
    );
  });

  it("rejects empty token", async () => {
    await expect(verifyScopeToken("", TEST_PUBLIC_KEY)).rejects.toThrow("No scope token");
  });

  it("rejects malformed token (no dot)", async () => {
    await expect(verifyScopeToken("not-a-valid-token", TEST_PUBLIC_KEY)).rejects.toThrow(
      "Malformed token",
    );
  });

  it("rejects token with 3 parts", async () => {
    await expect(verifyScopeToken("a.b.c", TEST_PUBLIC_KEY)).rejects.toThrow(
      "Malformed token",
    );
  });

  it("rejects invalid JSON payload", async () => {
    const badPayload = Buffer.from("not json").toString("base64url");
    const sig = sign(null, Buffer.from(badPayload), TEST_PRIVATE_KEY);
    const sigB64 = sig.toString("base64url");
    const token = `${badPayload}.${sigB64}`;

    await expect(verifyScopeToken(token, TEST_PUBLIC_KEY)).rejects.toThrow(
      "Invalid payload",
    );
  });

  it("rejects payload missing sub claim", async () => {
    const payload = validPayload();
    delete payload.sub;
    const token = makeScopeToken(payload);

    await expect(verifyScopeToken(token, TEST_PUBLIC_KEY)).rejects.toThrow(
      "Missing required claim",
    );
  });
});

describe("getCurrentScopeToken", () => {
  it("returns empty string when no context", () => {
    setScopeToken("");
    expect(getCurrentScopeToken()).toBe("");
  });

  it("returns token from fallback storage", () => {
    setScopeToken("test-token-value");
    expect(getCurrentScopeToken()).toBe("test-token-value");
    setScopeToken(""); // cleanup
  });
});

describe("requireScope", () => {
  it("succeeds with matching scope", async () => {
    const payload = validPayload({ scope: "data:pii:query exec:shell:run" });
    const token = makeScopeToken(payload);

    const claims = await requireScope("data:pii:query", token, TEST_PUBLIC_KEY);
    expect(claims.sub).toBe("agent-123");
  });

  it("throws on missing scope", async () => {
    const payload = validPayload({ scope: "data:pii:query" });
    const token = makeScopeToken(payload);

    try {
      await requireScope("exec:shell:run", token, TEST_PUBLIC_KEY);
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ScopeVerificationError);
      const err = e as ScopeVerificationError;
      expect(err.reason).toContain("not granted");
      expect(err.claims).toBeDefined();
      expect(err.claims!.scope).toBe("data:pii:query");
    }
  });

  it("throws when no token available", async () => {
    setScopeToken("");
    await expect(requireScope("data:pii:query", undefined, TEST_PUBLIC_KEY)).rejects.toThrow(
      "No scope token available",
    );
  });

  it("throws on expired token", async () => {
    const payload = validPayload({ exp: Math.floor(Date.now() / 1000) - 60 });
    const token = makeScopeToken(payload);

    await expect(requireScope("data:pii:query", token, TEST_PUBLIC_KEY)).rejects.toThrow(
      "Token expired",
    );
  });
});

describe("ScopeVerificationError", () => {
  it("has correct message format", () => {
    const err = new ScopeVerificationError("bad token");
    expect(err.message).toBe("Scope verification failed: bad token");
    expect(err.reason).toBe("bad token");
    expect(err.claims).toBeUndefined();
    expect(err.name).toBe("ScopeVerificationError");
  });

  it("includes claims when provided", () => {
    const claims: ScopeTokenClaims = {
      sub: "a",
      scope: "s",
      tool: "t",
      binding: "b",
      exp: 0,
      rid: "r",
    };
    const err = new ScopeVerificationError("expired", claims);
    expect(err.claims).toBeDefined();
    expect(err.claims!.sub).toBe("a");
  });

  it("is instanceof Error", () => {
    const err = new ScopeVerificationError("test");
    expect(err).toBeInstanceOf(Error);
  });
});
