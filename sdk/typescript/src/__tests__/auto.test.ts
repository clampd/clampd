/**
 * Tests for src/auto.ts — zero-code auto-instrumentation primitives.
 *
 * The loader-hook wiring (module.register) is exercised end-to-end by the
 * `clampd run` launcher; here we cover the pieces that run in-process:
 * the construct-trap wrapper and DSN auto-init.
 */
import { describe, it, expect, vi } from "vitest";
import clampd from "../index.js";
import { __clampdWrap, autoInit } from "../instrument.js";
import * as config from "../config.js";

describe("__clampdWrap", () => {
  it("wraps the constructor so every instance is passed to the matching wrapper", () => {
    const seen: unknown[] = [];
    const spy = vi.spyOn(clampd, "openai").mockImplementation((c: unknown) => {
      seen.push(c);
      return c as never;
    });

    class FakeOpenAI {
      inited = true;
      constructor(public opts: Record<string, unknown> = {}) {}
    }

    const Wrapped = __clampdWrap(FakeOpenAI as never, "openai");
    const inst = new (Wrapped as unknown as typeof FakeOpenAI)({ apiKey: "x" });

    expect(inst).toBeInstanceOf(FakeOpenAI); // prototype chain preserved
    expect((inst as FakeOpenAI).inited).toBe(true); // original ctor still ran
    expect(seen).toHaveLength(1); // wrapper applied to the instance
    spy.mockRestore();
  });

  it("routes anthropic kind to clampd.anthropic", () => {
    const spy = vi.spyOn(clampd, "anthropic").mockImplementation((c: unknown) => c as never);
    class FakeAnthropic {}
    const Wrapped = __clampdWrap(FakeAnthropic as never, "anthropic");
    new (Wrapped as unknown as typeof FakeAnthropic)();
    expect(spy).toHaveBeenCalledOnce();
    spy.mockRestore();
  });

  it("falls through to the original instance if wrapping throws (never fatal)", () => {
    const spy = vi.spyOn(clampd, "openai").mockImplementation(() => {
      throw new Error("boom");
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    class FakeOpenAI {
      tag = "raw";
    }
    const Wrapped = __clampdWrap(FakeOpenAI as never, "openai");
    const inst = new (Wrapped as unknown as typeof FakeOpenAI)();
    expect((inst as FakeOpenAI).tag).toBe("raw");
    spy.mockRestore();
    warn.mockRestore();
  });

  it("returns non-function inputs unchanged", () => {
    const notAClass = undefined as unknown as new () => object;
    expect(__clampdWrap(notAClass, "openai")).toBe(notAClass);
  });
});

describe("autoInit", () => {
  it("is a no-op when a client already exists (idempotent)", async () => {
    // setup.ts already called init() before this test, so defaultClient is set.
    expect(config.defaultClient).not.toBeNull();
    const before = config.defaultClient;
    await autoInit();
    expect(config.defaultClient).toBe(before);
  });

  it("auto-inits from CLAMPD_DSN when no client exists", async () => {
    config._reset();
    expect(config.defaultClient).toBeNull();
    process.env.CLAMPD_DSN = "clampd+http://ag_test_x@localhost:8080";
    await autoInit();
    expect(config.defaultClient).not.toBeNull();
  });
});
