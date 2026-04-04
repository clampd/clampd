/**
 * LangChain.js adapter for Clampd.
 *
 * Routes tool calls through the Clampd proxy so every LLM-initiated
 * action is classified, policy-checked, scoped, and audit-logged.
 *
 * Requires @langchain/core as a peer dependency.
 */

import { ClampdClient, type ProxyResponse } from "./client.js";

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

  return new DynamicStructuredTool({
    name: "database.query",
    description:
      "Execute a SQL query against the database. " +
      "The query is security-scanned before execution.",
    schema,
    func: async ({ query }: { query: string }): Promise<string> => {
      const result: ProxyResponse = await opts.client.proxy(
        "database.query",
        { query },
        targetUrl,
        `Agent executing SQL: ${query.slice(0, 200)}`,
      );

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
