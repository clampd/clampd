/**
 * Global test setup: clampd.init() now enrolls over the network, so stub
 * enrollment and auto-create a default client before each test. Mirrors the
 * Python SDK's conftest.
 */
import { beforeEach, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";

process.env.JWT_SECRET ||= "test-secret-for-sdk-tests-32chars!";

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

import * as config from "../config.js";

beforeEach(async () => {
  config._reset();
  process.env.CLAMPD_DSN = "clampd+http://ag_test_x@localhost:8080";
  await config.init();
});
