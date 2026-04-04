import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { makeAgentJwt } from "../auth.js";

function decodeB64Url(s: string): string {
  return Buffer.from(s, "base64url").toString();
}

describe("makeAgentJwt", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.JWT_SECRET;
  });
  afterEach(() => {
    process.env = originalEnv;
  });

  describe("unsigned (rejected since C3 fix)", () => {
    it("throws Error without secret", () => {
      expect(() => makeAgentJwt("agent-1")).toThrow("No signing secret available");
    });

    it("throws Error without env var", () => {
      delete process.env.JWT_SECRET;
      expect(() => makeAgentJwt("agent-1")).toThrow(Error);
    });
  });

  describe("signed (production)", () => {
    it("creates 3-part token NOT ending in .nosig", () => {
      const token = makeAgentJwt("agent-1", { secret: "test-key" });
      const parts = token.split(".");
      expect(parts).toHaveLength(3);
      expect(parts[2]).not.toBe("nosig");
    });

    it("header has alg: HS256", () => {
      const token = makeAgentJwt("agent-1", { secret: "test-key" });
      const header = JSON.parse(decodeB64Url(token.split(".")[0]));
      expect(header.alg).toBe("HS256");
    });

    it("different secrets produce different signatures", () => {
      const t1 = makeAgentJwt("agent-1", { secret: "key-a" });
      const t2 = makeAgentJwt("agent-1", { secret: "key-b" });
      expect(t1.split(".")[2]).not.toBe(t2.split(".")[2]);
    });

    it("includes scopes when provided", () => {
      const token = makeAgentJwt("agent-1", { secret: "s", scopes: ["db:read"] });
      const payload = JSON.parse(decodeB64Url(token.split(".")[1]));
      expect(payload.scopes).toEqual(["db:read"]);
    });

    it("respects JWT_SECRET env var", () => {
      process.env.JWT_SECRET = "env-secret";
      const token = makeAgentJwt("agent-1");
      expect(token.split(".")[2]).not.toBe("nosig");
    });

    it("custom ttlSeconds sets correct exp", () => {
      const token = makeAgentJwt("agent-1", { secret: "s", ttlSeconds: 120 });
      const payload = JSON.parse(decodeB64Url(token.split(".")[1]));
      expect(payload.exp - payload.iat).toBe(120);
    });
  });
});
