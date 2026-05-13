import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  registerTool,
  computeScope,
  validateClassification,
  ClampdClassificationError,
  contractHash,
  type ToolClassification,
} from "../index.js";
import { _registeredDescriptors } from "../_frameworkAdapters.js";

// Tests signing — matches the pattern in the other SDK tests.
process.env.JWT_SECRET = "test-secret-for-sdk-tests-32chars!";

// ── Helpers ─────────────────────────────────────────────────────────

function okResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => ({ ok: true }),
    text: async () => "ok",
  };
}

// ── Tests ───────────────────────────────────────────────────────────

describe("registerTool — valid classification", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(okResponse()));
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warnSpy.mockRestore();
    vi.unstubAllGlobals();
    delete process.env.CLAMPD_ORG_ID;
    delete process.env.CLAMPD_DASHBOARD_URL;
    delete process.env.CLAMPD_API_KEY;
  });

  it("POSTs the classified descriptor to the register endpoint", async () => {
    const mockFetch = vi.fn().mockResolvedValue(okResponse());
    vi.stubGlobal("fetch", mockFetch);

    const classification: ToolClassification = {
      category: "db",
      subcategory: "query",
      operation: "read",
    };

    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";

    await registerTool({
      name: "db.select_users",
      classification,
      description: "Run a SELECT query against the users table",
      apiKey: "key_abc",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];

    // SDK→gateway only. Gateway resolves org from X-AG-Key, computes
    // scope + descriptor_hash server-side.
    expect(url).toBe("http://gateway.example/v1/register");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(init.headers["X-AG-Key"]).toBe("key_abc");

    const body = JSON.parse(init.body as string);
    expect(body).toEqual({
      name: "db.select_users",
      category: "db",
      subcategory: "query",
      operation: "read",
      description: "Run a SELECT query against the users table",
      param_schema: {},
    });
  });

  it("picks up gateway URL + apiKey from env vars", async () => {
    const mockFetch = vi.fn().mockResolvedValue(okResponse());
    vi.stubGlobal("fetch", mockFetch);

    process.env.CLAMPD_GATEWAY_URL = "http://env.example/";
    process.env.CLAMPD_API_KEY = "key_env";

    await registerTool({
      name: "fs.read",
      classification: { category: "fs", subcategory: "file", operation: "read" },
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe("http://env.example/v1/register");
    expect(init.headers["X-AG-Key"]).toBe("key_env");
  });

  it("warns and skips when apiKey is missing", async () => {
    const mockFetch = vi.fn().mockResolvedValue(okResponse());
    vi.stubGlobal("fetch", mockFetch);

    await registerTool({
      name: "fs.read",
      classification: { category: "fs", subcategory: "file", operation: "read" },
    });

    expect(mockFetch).not.toHaveBeenCalled();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("no apiKey provided"),
    );
  });
});

describe("registerTool — invalid classification", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(okResponse()));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws ClampdClassificationError when the triple is bogus", async () => {
    // Escape hatch: caller bypassed the discriminated union via `as any`.
    // Runtime validation still protects the backend.
    const bogus = {
      category: "comms",
      subcategory: "shell", // invalid — shell is under exec, not comms
      operation: "run",
    } as unknown as ToolClassification;

    await expect(
      registerTool({
        name: "evil.tool",
        classification: bogus,
      }),
    ).rejects.toThrow(ClampdClassificationError);
  });

  it("throws when operation is not valid for the (category, subcategory)", async () => {
    // `db.query` only permits `read` — `write` must be rejected.
    const bogus = {
      category: "db",
      subcategory: "query",
      operation: "write",
    } as unknown as ToolClassification;

    await expect(
      registerTool({
        name: "db.mutate_via_query",
        classification: bogus,
      }),
    ).rejects.toThrow(ClampdClassificationError);
  });
});

describe("registerTool — backend unreachable", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warnSpy.mockRestore();
    vi.unstubAllGlobals();
  });

  it("logs a warning and does not throw when fetch rejects", async () => {
    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";
    process.env.CLAMPD_API_KEY = "key_test";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("ECONNREFUSED")),
    );

    await expect(
      registerTool({
        name: "db.q",
        classification: { category: "db", subcategory: "query", operation: "read" },
      }),
    ).resolves.toBeUndefined();

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("failed to reach gateway"),
    );
  });

  it("logs a warning and does not throw when the gateway returns non-2xx", async () => {
    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";
    process.env.CLAMPD_API_KEY = "key_test";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: "boom" }),
        text: async () => "internal error",
      }),
    );

    await expect(
      registerTool({
        name: "db.q",
        classification: { category: "db", subcategory: "query", operation: "read" },
      }),
    ).resolves.toBeUndefined();

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("gateway returned 500"),
    );
  });
});

describe("computeScope", () => {
  it("formats as category:subcategory:operation", () => {
    expect(
      computeScope({ category: "db", subcategory: "query", operation: "read" }),
    ).toBe("db:query:read");

    expect(
      computeScope({
        category: "auth",
        subcategory: "token",
        operation: "refresh",
      }),
    ).toBe("auth:token:refresh");

    expect(
      computeScope({
        category: "payment",
        subcategory: "transaction",
        operation: "destructive",
      }),
    ).toBe("payment:transaction:destructive");
  });
});

describe("registerTool framework-object overload", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn().mockResolvedValue(okResponse());
    vi.stubGlobal("fetch", mockFetch);
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    _registeredDescriptors.clear();
  });
  afterEach(() => {
    warnSpy.mockRestore();
    vi.unstubAllGlobals();
    _registeredDescriptors.clear();
    delete process.env.CLAMPD_GATEWAY_URL;
    delete process.env.CLAMPD_API_KEY;
  });

  it("langchain Tool overload — accepts a stub { name, description, schema }", async () => {
    // Minimal stub matching the LangChain BaseTool duck-type:
    // .name + .schema (or .args_schema). Using a JSON-schema-style
    // object (not a zod instance) so the descriptor extraction lands
    // in the plain-object branch deterministically.
    const lcTool = {
      name: "lc.search",
      description: "Search the docs",
      schema: { type: "object", properties: { q: { type: "string" } } },
    };

    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";

    await registerTool(lcTool, {
      category: "comms",
      subcategory: "messaging",
      operation: "send",
      apiKey: "key_lc",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe("http://gateway.example/v1/register");
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe("lc.search");
    expect(body.description).toBe("Search the docs");
    expect(body.param_schema).toEqual({
      type: "object",
      properties: { q: { type: "string" } },
    });
    expect(body.descriptor_hash).toBeUndefined(); // gateway computes server-side

    // Hash is recorded process-locally and matches what contractHash
    // would compute for the extracted triple.
    const expectedHash = contractHash({
      name: "lc.search",
      description: "Search the docs",
      parameters: { type: "object", properties: { q: { type: "string" } } },
    });
    expect(_registeredDescriptors.get("lc.search")).toBe(expectedHash);
  });

  it("OpenAI tool dict overload — accepts { type:'function', function:{...} }", async () => {
    const openaiTool = {
      type: "function",
      function: {
        name: "weather.lookup",
        description: "Look up the current weather",
        parameters: {
          type: "object",
          properties: { city: { type: "string" } },
          required: ["city"],
        },
      },
    };

    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";

    await registerTool(openaiTool, {
      category: "comms",
      subcategory: "messaging",
      operation: "send",
      apiKey: "key_oa",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [, init] = mockFetch.mock.calls[0];
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe("weather.lookup");
    expect(body.description).toBe("Look up the current weather");
    expect(body.param_schema).toEqual(openaiTool.function.parameters);
    expect(body.descriptor_hash).toBeUndefined(); // gateway computes server-side

    const expectedHash = contractHash({
      name: "weather.lookup",
      description: "Look up the current weather",
      parameters: openaiTool.function.parameters,
    });
    expect(_registeredDescriptors.get("weather.lookup")).toBe(expectedHash);
  });

  it("Anthropic tool dict overload — accepts { name, description, input_schema }", async () => {
    const anthropicTool = {
      name: "calc.add",
      description: "Add two numbers",
      input_schema: {
        type: "object",
        properties: { a: { type: "number" }, b: { type: "number" } },
        required: ["a", "b"],
      },
    };

    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";

    await registerTool(anthropicTool, {
      category: "db",
      subcategory: "query",
      operation: "read",
      apiKey: "key_an",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [, init] = mockFetch.mock.calls[0];
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe("calc.add");
    expect(body.description).toBe("Add two numbers");
    expect(body.param_schema).toEqual(anthropicTool.input_schema);
    expect(body.descriptor_hash).toBeUndefined(); // gateway computes server-side

    const expectedHash = contractHash({
      name: "calc.add",
      description: "Add two numbers",
      parameters: anthropicTool.input_schema,
    });
    expect(_registeredDescriptors.get("calc.add")).toBe(expectedHash);
  });

  it("throws when both object and explicit description/paramSchema supplied", async () => {
    const lcTool = {
      name: "lc.search",
      description: "Search the docs",
      schema: { type: "object" },
    };

    await expect(
      registerTool(lcTool, {
        category: "comms",
        subcategory: "messaging",
        operation: "send",
        // @ts-expect-error — RegisterToolClassificationOnly forbids
        // these on form 3, the runtime check is the belt-and-suspenders.
        description: "Override description",
      }),
    ).rejects.toThrow(/description\/paramSchema OR a tool object, not both/);

    await expect(
      registerTool(lcTool, {
        category: "comms",
        subcategory: "messaging",
        operation: "send",
        // @ts-expect-error — same as above for paramSchema.
        paramSchema: { type: "object" },
      }),
    ).rejects.toThrow(/description\/paramSchema OR a tool object, not both/);
  });

  it("throws when unrecognised object passed", async () => {
    await expect(
      registerTool(
        { foo: 1 } as unknown as object,
        {
          category: "comms",
          subcategory: "messaging",
          operation: "send",
        },
      ),
    ).rejects.toThrow(/not a recognised tool object/);
  });

  it("string form still works — backward compat regression", async () => {
    process.env.CLAMPD_GATEWAY_URL = "http://gateway.example";

    await registerTool("legacy.tool", {
      category: "db",
      subcategory: "query",
      operation: "read",
      description: "Legacy form via name string",
      paramSchema: { type: "object", properties: { id: { type: "string" } } },
      apiKey: "key_legacy",
    });

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe("http://gateway.example/v1/register");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({
      name: "legacy.tool",
      category: "db",
      subcategory: "query",
      operation: "read",
      description: "Legacy form via name string",
      param_schema: { type: "object", properties: { id: { type: "string" } } },
    });
    expect(_registeredDescriptors.get("legacy.tool")).toBeDefined();
  });
});

describe("validateClassification", () => {
  it("accepts triples present in the taxonomy", () => {
    expect(validateClassification("db", "query", "read")).toBe(true);
    expect(validateClassification("auth", "token", "refresh")).toBe(true);
    expect(validateClassification("exec", "shell", "destructive")).toBe(true);
  });

  it("rejects unknown categories", () => {
    expect(validateClassification("bogus", "query", "read")).toBe(false);
  });

  it("rejects unknown subcategories", () => {
    expect(validateClassification("comms", "shell", "run")).toBe(false);
  });

  it("rejects operations not permitted for that (cat, sub)", () => {
    expect(validateClassification("db", "query", "write")).toBe(false);
    expect(validateClassification("llm", "input", "read")).toBe(false);
  });
});
