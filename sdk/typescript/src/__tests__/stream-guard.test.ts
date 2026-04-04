import { describe, it, expect, vi, beforeEach } from "vitest";
import clampd, { ClampdBlockedError } from "../index.js";

process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

function mockProxyResponse(allowed = true) {
  return {
    request_id: "req-stream",
    allowed,
    risk_score: allowed ? 0.05 : 0.92,
    denial_reason: allowed ? null : "Blocked by policy",
    latency_ms: 3,
    degraded_stages: [],
    session_flags: [],
    matched_rules: allowed ? [] : ["R001"],
  };
}

/** Helper to create an async iterable from an array. */
async function* fromArray<T>(items: T[]): AsyncIterableIterator<T> {
  for (const item of items) {
    yield item;
  }
}

/** Wrap an async generator to look like a stream object with Symbol.asyncIterator. */
function makeStream<T>(items: T[]): AsyncIterable<T> & { extra: string } {
  return {
    extra: "preserved",
    [Symbol.asyncIterator]: () => fromArray(items),
  };
}

/** Collect all items from an async iterable. */
async function collect<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const items: T[] = [];
  for await (const item of iter) {
    items.push(item);
  }
  return items;
}

// ── OpenAI streaming ─────────────────────────────────────────────

describe("OpenAI stream guard", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("passes text-only chunks through immediately without proxy calls", async () => {
    // scanInput is disabled to isolate the stream guard behavior
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const chunks = [
      { choices: [{ delta: { content: "Hello" }, finish_reason: null }] },
      { choices: [{ delta: { content: " world" }, finish_reason: null }] },
      { choices: [{ delta: {}, finish_reason: "stop" }] },
    ];

    const stream = makeStream(chunks);
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(stream) } } };
    const wrapped = clampd.openai(oai, { agentId: "test", scanInput: false, scanOutput: false, guardStream: true });

    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "hi" }],
      stream: true,
      tools: [{ type: "function", function: { name: "search" } }],
    });

    const collected = await collect(result as AsyncIterable<unknown>);
    expect(collected).toHaveLength(3);
    // No proxy calls for text-only
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("buffers tool call chunks, guards them, then releases", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const chunks = [
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { name: "search", arguments: '{"q":' } }] }, finish_reason: null }] },
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '"test"}' } }] }, finish_reason: null }] },
      { choices: [{ delta: {}, finish_reason: "tool_calls" }] },
    ];

    const stream = makeStream(chunks);
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(stream) } } };
    const wrapped = clampd.openai(oai, { agentId: "test", guardStream: true });

    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [],
      stream: true,
      tools: [{ type: "function", function: { name: "search" } }],
    });

    const collected = await collect(result as AsyncIterable<unknown>);
    // All chunks eventually released: 2 tool chunks + 1 finish chunk
    expect(collected).toHaveLength(3);
  });

  it("throws ClampdBlockedError when tool call is denied", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false),
    }));

    const chunks = [
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { name: "rm_rf", arguments: '{}' } }] }, finish_reason: null }] },
      { choices: [{ delta: {}, finish_reason: "tool_calls" }] },
    ];

    const stream = makeStream(chunks);
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(stream) } } };
    const wrapped = clampd.openai(oai, { agentId: "test", guardStream: true });

    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [],
      stream: true,
      tools: [{ type: "function", function: { name: "rm_rf" } }],
    });

    await expect(collect(result as AsyncIterable<unknown>)).rejects.toThrow(ClampdBlockedError);
  });

  it("guards multiple tool calls in a single stream", async () => {
    const fetchCalls: string[] = [];
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string);
      fetchCalls.push(body.tool);
      return { ok: true, json: async () => mockProxyResponse(true) };
    }));

    const chunks = [
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { name: "search", arguments: '{"q":"a"}' } }] }, finish_reason: null }] },
      { choices: [{ delta: { tool_calls: [{ index: 1, function: { name: "fetch", arguments: '{"url":"b"}' } }] }, finish_reason: null }] },
      { choices: [{ delta: {}, finish_reason: "tool_calls" }] },
    ];

    const stream = makeStream(chunks);
    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(stream) } } };
    const wrapped = clampd.openai(oai, { agentId: "test", guardStream: true });

    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [],
      stream: true,
      tools: [{ type: "function", function: { name: "search" } }, { type: "function", function: { name: "fetch" } }],
    });

    await collect(result as AsyncIterable<unknown>);
    expect(fetchCalls).toContain("search");
    expect(fetchCalls).toContain("fetch");
  });

  it("preserves extra properties on the stream object via Proxy", async () => {
    vi.stubGlobal("fetch", vi.fn());

    const stream = makeStream([
      { choices: [{ delta: { content: "hi" }, finish_reason: "stop" }] },
    ]);

    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(stream) } } };
    const wrapped = clampd.openai(oai, { agentId: "test", guardStream: true });

    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [],
      stream: true,
      tools: [{ type: "function", function: { name: "x" } }],
    }) as AsyncIterable<unknown> & { extra: string };

    expect(result.extra).toBe("preserved");
  });

  it("skips stream wrapping when no tools are defined", async () => {
    vi.stubGlobal("fetch", vi.fn());

    const stream = makeStream([
      { choices: [{ delta: { content: "hi" }, finish_reason: "stop" }] },
    ]);

    const oai = { chat: { completions: { create: vi.fn().mockResolvedValue(stream) } } };
    const wrapped = clampd.openai(oai, { agentId: "test", guardStream: true });

    const result = await wrapped.chat.completions.create({
      model: "gpt-4o",
      messages: [],
      stream: true,
      // No tools
    });

    // Should return the raw stream (same reference)
    expect(result).toBe(stream);
  });
});

// ── Anthropic streaming ──────────────────────────────────────────

describe("Anthropic stream guard", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("passes text events through immediately", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const events = [
      { type: "message_start", message: {} },
      { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
      { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Hello" } },
      { type: "content_block_stop", index: 0 },
      { type: "message_stop" },
    ];

    const stream = makeStream(events);
    const anth = { messages: { create: vi.fn().mockResolvedValue(stream) } };
    const wrapped = clampd.anthropic(anth, { agentId: "test", scanInput: false, scanOutput: false, guardStream: true });

    const result = await wrapped.messages.create({
      model: "claude-sonnet-4-6",
      messages: [{ role: "user", content: "hi" }],
      max_tokens: 100,
      stream: true,
      tools: [{ name: "search" }],
    });

    const collected = await collect(result as AsyncIterable<unknown>);
    expect(collected).toHaveLength(5);
    // No proxy calls for text-only
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("buffers tool_use events, guards them, then releases", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(true),
    }));

    const events = [
      { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "tu_1", name: "search" } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: '{"q":' } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: '"test"}' } },
      { type: "content_block_stop", index: 0 },
      { type: "message_stop" },
    ];

    const stream = makeStream(events);
    const anth = { messages: { create: vi.fn().mockResolvedValue(stream) } };
    const wrapped = clampd.anthropic(anth, { agentId: "test", guardStream: true });

    const result = await wrapped.messages.create({
      model: "claude-sonnet-4-6",
      messages: [],
      max_tokens: 100,
      stream: true,
      tools: [{ name: "search" }],
    });

    const collected = await collect(result as AsyncIterable<unknown>);
    // 4 tool events + 1 message_stop
    expect(collected).toHaveLength(5);
  });

  it("throws ClampdBlockedError when tool_use is denied", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockProxyResponse(false),
    }));

    const events = [
      { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "tu_1", name: "dangerous" } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: '{}' } },
      { type: "content_block_stop", index: 0 },
    ];

    const stream = makeStream(events);
    const anth = { messages: { create: vi.fn().mockResolvedValue(stream) } };
    const wrapped = clampd.anthropic(anth, { agentId: "test", guardStream: true });

    const result = await wrapped.messages.create({
      model: "claude-sonnet-4-6",
      messages: [],
      max_tokens: 100,
      stream: true,
      tools: [{ name: "dangerous" }],
    });

    await expect(collect(result as AsyncIterable<unknown>)).rejects.toThrow(ClampdBlockedError);
  });

  it("handles mixed text + tool_use blocks", async () => {
    const proxyCallCount = { n: 0 };
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => {
      proxyCallCount.n++;
      return { ok: true, json: async () => mockProxyResponse(true) };
    }));

    const events = [
      { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
      { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Let me search" } },
      { type: "content_block_stop", index: 0 },
      { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "tu_1", name: "search" } },
      { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"q":"test"}' } },
      { type: "content_block_stop", index: 1 },
      { type: "message_stop" },
    ];

    const stream = makeStream(events);
    const anth = { messages: { create: vi.fn().mockResolvedValue(stream) } };
    const wrapped = clampd.anthropic(anth, { agentId: "test", guardStream: true });

    const result = await wrapped.messages.create({
      model: "claude-sonnet-4-6",
      messages: [],
      max_tokens: 100,
      stream: true,
      tools: [{ name: "search" }],
    });

    const collected = await collect(result as AsyncIterable<unknown>);
    expect(collected).toHaveLength(7); // All events eventually yielded
    expect(proxyCallCount.n).toBe(1); // Only the tool_use block triggered a proxy call
  });
});
