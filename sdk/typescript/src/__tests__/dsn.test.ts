import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { parseDsn, DEFAULT_GATEWAY_URL } from "../dsn.js";
import * as config from "../config.js";

const { init, sharedConfig } = config;

// init() enrolls over the network; stub enroll so unit tests run offline.
vi.mock("../enroll.js", async (orig) => {
  const actual = await orig<typeof import("../enroll.js")>();
  return {
    ...actual,
    enroll: async (_host: string, _org: string, name: string) => ({
      privateKey: generateKeyPairSync("ed25519").privateKey,
      agentId: `uuid-${name}`,
    }),
  };
});

// Vectors mirror the Python SDK (tests/test_dsn.py) to keep parsing identical.
const PARSE_VECTORS: [string, string, string][] = [
  ["clampd://ag_live_abc123@gateway.clampd.dev", "https://gateway.clampd.dev", "ag_live_abc123"],
  ["clampd://ag_live_abc123@", DEFAULT_GATEWAY_URL, "ag_live_abc123"],
  ["clampd://ag_test_x@gateway.clampd.dev:8443", "https://gateway.clampd.dev:8443", "ag_test_x"],
  ["clampd+http://ag_test_x@localhost:8080", "http://localhost:8080", "ag_test_x"],
  ["https://ag_live_z@gw.example.com", "https://gw.example.com", "ag_live_z"],
];

describe("parseDsn", () => {
  it.each(PARSE_VECTORS)("parses %s", (dsn, gatewayUrl, apiKey) => {
    expect(parseDsn(dsn)).toEqual({ gatewayUrl, apiKey });
  });

  it.each([
    "",
    "   ",
    "clampd://gateway.clampd.dev", // no org key
    "ftp://ag_live_x@gateway.clampd.dev", // bad scheme
    "ag_live_x@gateway.clampd.dev", // no scheme
  ])("rejects %s", (bad) => {
    expect(() => parseDsn(bad)).toThrow();
  });
});

describe("init() DSN resolution", () => {
  const ENV = ["CLAMPD_DSN", "CLAMPD_AGENT_NAME"];
  beforeEach(() => {
    for (const k of ENV) delete process.env[k];
    config._reset();
  });
  afterEach(() => {
    for (const k of ENV) delete process.env[k];
    config._reset();
  });

  it("derives gatewayUrl + apiKey from CLAMPD_DSN", async () => {
    process.env.CLAMPD_DSN = "clampd://ag_live_env@gateway.clampd.dev";
    await init();
    expect(config.sharedConfig.gatewayUrl).toBe("https://gateway.clampd.dev");
    expect(config.sharedConfig.apiKey).toBe("ag_live_env");
  });

  it("accepts a dsn argument", async () => {
    await init({ dsn: "clampd+http://ag_test_arg@localhost:8080" });
    expect(config.sharedConfig.gatewayUrl).toBe("http://localhost:8080");
    expect(config.sharedConfig.apiKey).toBe("ag_test_arg");
  });

  it("enrolls using the logical name", async () => {
    await init({ dsn: "clampd://ag_live_x@gateway.clampd.dev", name: "billing" });
    expect(config.defaultClient?.agentId).toBe("uuid-billing");
  });

  it("throws when no DSN is configured", async () => {
    delete process.env.CLAMPD_DSN;
    await expect(init()).rejects.toThrow();
  });
});
