import { createHash } from "node:crypto";
import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import clampd, { ClampdClient, ClampdBlockedError } from "../index.js";

// All tests need a signing secret since C3 fix (unsigned JWTs rejected)
process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

function mockProxyResponse(allowed = true, denial_reason: string | null = null) {
  return {
    request_id: "req-test",
    allowed,
    risk_score: allowed ? 0.1 : 0.95,
    denial_reason,
    latency_ms: 5,
    degraded_stages: [],
    session_flags: [],
    scope_granted: allowed ? "db:read" : null,
    tool_response: allowed ? "ok" : null,
  };
}

describe("clampd.guard()", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("executes wrapped function when allowed", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = vi.fn().mockResolvedValue("result");
    const guarded = clampd.guard(fn, { agentId: "test", toolName: "db.query" });
    const result = await guarded({ sql: "SELECT 1" });

    expect(result).toBe("result");
    expect(fn).toHaveBeenCalledOnce();
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  it("throws ClampdBlockedError when denied", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false, "dangerous"),
    }));

    const fn = vi.fn().mockResolvedValue("result");
    const guarded = clampd.guard(fn, { agentId: "test", toolName: "db.query" });

    await expect(guarded({ sql: "DROP TABLE" })).rejects.toThrow(ClampdBlockedError);
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("clampd.openai()", () => {
  it("passes through when no tool calls", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true, risk_score: 0, matched_rules: [], latency_ms: 1 }),
    }));

    const response = {
      choices: [{ finish_reason: "stop", message: { content: "Hello", tool_calls: [] } }],
    };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(response) } } };

    const wrapped = clampd.openai(oai, { agentId: "test" });
    const result = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [] });

    expect(result).toBe(response);
  });

  it("allows tool calls when proxy allows", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const response = {
      choices: [{
        finish_reason: "tool_calls",
        message: {
          tool_calls: [{
            id: "tc-1",
            type: "function",
            function: { name: "search", arguments: '{"q":"test"}' },
          }],
        },
      }],
    };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(response) } } };

    const wrapped = clampd.openai(oai, { agentId: "test" });
    const result = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [] });

    expect(result).toBe(response);
  });

  it("throws when proxy denies tool call", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false, "blocked"),
    }));

    const response = {
      choices: [{
        finish_reason: "tool_calls",
        message: {
          tool_calls: [{
            id: "tc-1",
            type: "function",
            function: { name: "dangerous", arguments: '{}' },
          }],
        },
      }],
    };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(response) } } };

    const wrapped = clampd.openai(oai, { agentId: "test" });
    await expect(wrapped.chat.completions.create({ model: "gpt-4o", messages: [] }))
      .rejects.toThrow(ClampdBlockedError);
  });
});

describe("clampd.anthropic()", () => {
  it("passes through when no tool_use", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true, risk_score: 0, matched_rules: [], latency_ms: 1 }),
    }));

    const response = {
      stop_reason: "end_turn",
      content: [{ type: "text", text: "Hello" }],
    };
    const anth = { messages: { create: vi.fn().mockResolvedValue(response) } };

    const wrapped = clampd.anthropic(anth, { agentId: "test" });
    const result = await wrapped.messages.create({ model: "claude-sonnet-4-6", messages: [], max_tokens: 100 });

    expect(result).toBe(response);
  });

  it("allows tool_use when proxy allows", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const response = {
      stop_reason: "tool_use",
      content: [
        { type: "text", text: "I'll search" },
        { type: "tool_use", id: "tu-1", name: "search", input: { q: "test" } },
      ],
    };
    const anth = { messages: { create: vi.fn().mockResolvedValue(response) } };

    const wrapped = clampd.anthropic(anth, { agentId: "test" });
    const result = await wrapped.messages.create({ model: "claude-sonnet-4-6", messages: [], max_tokens: 100 });

    expect(result).toBe(response);
  });

  it("throws when proxy denies tool_use", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false, "denied"),
    }));

    const response = {
      stop_reason: "tool_use",
      content: [{ type: "tool_use", id: "tu-1", name: "rm_rf", input: {} }],
    };
    const anth = { messages: { create: vi.fn().mockResolvedValue(response) } };

    const wrapped = clampd.anthropic(anth, { agentId: "test" });
    await expect(wrapped.messages.create({ model: "claude-sonnet-4-6", messages: [], max_tokens: 100 }))
      .rejects.toThrow(ClampdBlockedError);
  });
});

describe("response checking", () => {
  it("guard with checkResponse inspects return value", async () => {
    let callCount = 0;
    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      callCount++;
      return {
        ok: true,
        json: async () => mockProxyResponse(true),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = vi.fn().mockResolvedValue("result with PII");
    const guarded = clampd.guard(fn, { agentId: "test", toolName: "db.query", checkResponse: true });
    const result = await guarded({ sql: "SELECT 1" });

    expect(result).toBe("result with PII");
    // Two fetch calls: proxy + inspect (PII detection handled server-side by /v1/inspect)
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("guard with checkResponse throws when inspect denies", async () => {
    let callCount = 0;
    const mockFetch = vi.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        return { ok: true, json: async () => mockProxyResponse(true) };
      }
      return { ok: true, json: async () => mockProxyResponse(false, "PII detected") };
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = vi.fn().mockResolvedValue("SSN: 123-45-6789");
    const guarded = clampd.guard(fn, { agentId: "test", toolName: "db.query", checkResponse: true });

    await expect(guarded({ sql: "SELECT ssn" })).rejects.toThrow(ClampdBlockedError);
  });

  it("guard without checkResponse skips inspect", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = vi.fn().mockResolvedValue("result");
    const guarded = clampd.guard(fn, { agentId: "test", toolName: "db.query" });
    await guarded({ sql: "SELECT 1" });

    // Should call fetch only once (proxy only, no inspect)
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe("clampd.tools()", () => {
  it("wraps OpenAI tool execute functions", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const original = vi.fn().mockResolvedValue("weather: sunny");
    const myTools = [{
      type: "function" as const,
      function: { name: "get_weather", execute: original },
    }];

    const guarded = clampd.tools(myTools, { agentId: "test" });
    const result = await guarded[0].function.execute!({ city: "NYC" });

    expect(result).toBe("weather: sunny");
    expect(original).toHaveBeenCalledWith({ city: "NYC" });
  });

  it("passes through tools without execute", () => {
    const myTools = [{
      type: "function" as const,
      function: { name: "get_weather", description: "Get weather" },
    }];

    const guarded = clampd.tools(myTools, { agentId: "test" });
    expect(guarded[0]).toBe(myTools[0]);
  });
});

describe("tool descriptor hash", () => {
  it("guard sends tool_descriptor_hash in proxy request body", async () => {
    let capturedBody: Record<string, unknown> = {};
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedBody = JSON.parse(init.body as string);
      return {
        ok: true,
        json: async () => mockProxyResponse(true),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = vi.fn().mockResolvedValue("result");
    const guarded = clampd.guard(fn, { agentId: "test", toolName: "db.query" });
    await guarded({ sql: "SELECT 1" });

    expect(capturedBody.tool_descriptor_hash).toBeDefined();
    expect(typeof capturedBody.tool_descriptor_hash).toBe("string");
    expect((capturedBody.tool_descriptor_hash as string).length).toBe(64);
  });

  it("same function produces the same hash", async () => {
    const bodies: Record<string, unknown>[] = [];
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      bodies.push(JSON.parse(init.body as string));
      return {
        ok: true,
        json: async () => mockProxyResponse(true),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn = async (args: { sql: string }) => "result";
    const guarded1 = clampd.guard(fn, { agentId: "test", toolName: "db.query" });
    await guarded1({ sql: "SELECT 1" });

    const guarded2 = clampd.guard(fn, { agentId: "test", toolName: "db.query" });
    await guarded2({ sql: "SELECT 2" });

    expect(bodies[0].tool_descriptor_hash).toBe(bodies[1].tool_descriptor_hash);
  });

  it("different functions produce different hashes", async () => {
    const bodies: Record<string, unknown>[] = [];
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      bodies.push(JSON.parse(init.body as string));
      return {
        ok: true,
        json: async () => mockProxyResponse(true),
      };
    });
    vi.stubGlobal("fetch", mockFetch);

    const fn1 = async (args: { sql: string }) => "result";
    const fn2 = async (args: { sql: string; limit: number }) => "result with limit";

    const guarded1 = clampd.guard(fn1, { agentId: "test", toolName: "db.query" });
    await guarded1({ sql: "SELECT 1" });

    const guarded2 = clampd.guard(fn2, { agentId: "test", toolName: "db.query" });
    await guarded2({ sql: "SELECT 1", limit: 10 });

    expect(bodies[0].tool_descriptor_hash).not.toBe(bodies[1].tool_descriptor_hash);
  });
});

describe("streaming passthrough", () => {
  it("openai stream=true returns original response without proxy calls", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const streamResponse = { id: "stream-1", object: "chat.completion.chunk" };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(streamResponse) } } };

    const wrapped = clampd.openai(oai, { agentId: "test" });
    const result = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [], stream: true });

    expect(result).toBe(streamResponse);
    // No proxy/fetch calls: messages is empty so scanInput has nothing to scan
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("anthropic stream=true returns original response without proxy calls", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const streamResponse = { type: "message_start" };
    const anth = { messages: { create: vi.fn().mockResolvedValue(streamResponse) } };

    const wrapped = clampd.anthropic(anth, { agentId: "test" });
    const result = await wrapped.messages.create({ model: "claude-sonnet-4-6", messages: [], max_tokens: 100, stream: true });

    expect(result).toBe(streamResponse);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("openai stream=true with scanInput still scans before passthrough", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        allowed: true,
        risk_score: 0.05,
        denial_reason: null,
        matched_rules: [],
        latency_ms: 3,
      }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const streamResponse = { id: "stream-2" };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(streamResponse) } } };

    const wrapped = clampd.openai(oai, { agentId: "test", scanInput: true });
    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "hello" }],
      stream: true,
    });

    expect(result).toBe(streamResponse);
    // scanInput should have triggered one fetch call
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe("array validation on tool calls", () => {
  it("openai handles null tool_calls without crashing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true, risk_score: 0, matched_rules: [], latency_ms: 1 }),
    }));

    const response = {
      choices: [{
        finish_reason: "tool_calls",
        message: { content: "Hello", tool_calls: null },
      }],
    };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(response) } } };

    const wrapped = clampd.openai(oai, { agentId: "test" });
    const result = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [] });

    expect(result).toBe(response);
  });

  it("openai handles undefined tool_calls without crashing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true, risk_score: 0, matched_rules: [], latency_ms: 1 }),
    }));

    const response = {
      choices: [{
        finish_reason: "tool_calls",
        message: { content: "Hello" },
      }],
    };
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(response) } } };

    const wrapped = clampd.openai(oai, { agentId: "test" });
    const result = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [] });

    expect(result).toBe(response);
  });

  it("anthropic handles null content without crashing", async () => {
    vi.stubGlobal("fetch", vi.fn());

    const response = {
      stop_reason: "tool_use",
      content: null,
    };
    const anth = { messages: { create: vi.fn().mockResolvedValue(response) } };

    const wrapped = clampd.anthropic(anth, { agentId: "test" });
    const result = await wrapped.messages.create({ model: "claude-sonnet-4-6", messages: [], max_tokens: 100 });

    expect(result).toBe(response);
  });

  it("anthropic handles non-array content without crashing", async () => {
    vi.stubGlobal("fetch", vi.fn());

    const response = {
      stop_reason: "tool_use",
      content: "unexpected string",
    };
    const anth = { messages: { create: vi.fn().mockResolvedValue(response) } };

    const wrapped = clampd.anthropic(anth, { agentId: "test" });
    const result = await wrapped.messages.create({ model: "claude-sonnet-4-6", messages: [], max_tokens: 100 });

    expect(result).toBe(response);
  });
});
