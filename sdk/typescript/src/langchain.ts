/**
 * LangChain.js adapter for Clampd.
 *
 * Routes tool calls through the Clampd proxy so every LLM-initiated
 * action is classified, policy-checked, scoped, and audit-logged.
 *
 * Requires @langchain/core as a peer dependency.
 */

import { ClampdClient, type ProxyResponse } from "./client.js";
import { contractHash } from "./contract-hash.js";
import { raiseIfUnregistered, _registeredDescriptors } from "./_frameworkAdapters.js";

// ── Lazy imports with helpful errors ───────────────────────────────

async function loadDeps() {
  let DynamicStructuredTool: typeof import("@langchain/core/tools").DynamicStructuredTool;
  let z: typeof import("zod").z;

  try {
    const toolsMod = await import("@langchain/core/tools");
    DynamicStructuredTool = toolsMod.DynamicStructuredTool;
  } catch {
    throw new Error(
      "@langchain/core is required for the LangChain adapter. " +
        "Install with: npm install @langchain/core",
    );
  }

  try {
    const zodMod = await import("zod");
    z = zodMod.z;
  } catch {
    throw new Error(
      "zod is required for the LangChain adapter. " +
        "Install with: npm install zod",
    );
  }

  return { DynamicStructuredTool, z };
}

// ── Options ────────────────────────────────────────────────────────

export interface ClampdDatabaseToolOptions {
  client: ClampdClient;
  targetUrl?: string;
}

// ── Factory ────────────────────────────────────────────────────────

/**
 * Create a LangChain DynamicStructuredTool that proxies database
 * queries through the Clampd 9-stage security pipeline.
 *
 * ```ts
 * const tool = await createClampdDatabaseTool({ client });
 * const result = await tool.invoke({ query: "SELECT 1" });
 * ```
 */
export async function createClampdDatabaseTool(
  opts: ClampdDatabaseToolOptions,
) {
  const { DynamicStructuredTool, z } = await loadDeps();
  const targetUrl = opts.targetUrl ?? "http://mock-tool:5555";

  const schema = z.object({
    query: z.string().describe("SQL query to execute"),
  });

  const toolName = "database.query";
  const toolDescription =
    "Execute a SQL query against the database. " +
    "The query is security-scanned before execution.";

  // Compute the descriptor hash once at wrap time. zod 4 exposes
  // `z.toJSONSchema()` natively — no extra dependency required.
  // The resulting JSON Schema is content-hashed together with name
  // and description so rug-pull detection matches a pre-registered
  // descriptor in the dashboard.
  let parameters: object = {};
  try {
    parameters = z.toJSONSchema(schema) as object;
  } catch {
    // Fallback: leave parameters empty if conversion fails. The tool
    // still works; rug-pull detection degrades to "hash mismatch,
    // informational only" rather than blocking the call.
    parameters = {};
  }
  const computedHash = contractHash({
    name: toolName,
    description: toolDescription,
    parameters,
  });

  return new DynamicStructuredTool({
    name: toolName,
    description: toolDescription,
    schema,
    func: async ({ query }: { query: string }): Promise<string> => {
      // Prefer the hash registered via clampd.registerTool() so this
      // adapter agrees with whatever the dashboard last approved.
      const descriptorHash =
        _registeredDescriptors.get(toolName) ?? computedHash;
      const result: ProxyResponse = await opts.client.proxy(
        toolName,
        { query },
        targetUrl,
        `Agent executing SQL: ${query.slice(0, 200)}`,
        descriptorHash,
      );

      // Surface unregistered-tool denials as a typed exception. The
      // factory's normal "blocked" path returns a string so the
      // LangChain agent sees a tool-result message rather than an
      // exception — but unregistered tools are a developer error,
      // not a runtime policy decision, so they should throw.
      raiseIfUnregistered(toolName, result);

      if (!result.allowed) {
        return (
          `BLOCKED: ${result.denial_reason} ` +
          `(risk_score=${result.risk_score.toFixed(2)}, ` +
          `latency=${result.latency_ms}ms)`
        );
      }

      return (
        `ALLOWED: ${JSON.stringify(result.tool_response)} ` +
        `(risk_score=${result.risk_score.toFixed(2)}, ` +
        `scope=${result.scope_granted}, ` +
        `latency=${result.latency_ms}ms)`
      );
    },
  });
}
