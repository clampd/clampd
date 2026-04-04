/**
 * Example: Clampd + GitHub Models (FREE GPT-4o access)
 *
 * Uses GitHub Models inference API — no paid OpenAI key needed.
 * Just a GitHub personal access token (PAT) with no special scopes.
 *
 * Setup:
 *   1. Get a GitHub token: https://github.com/settings/tokens (no scopes needed)
 *   2. Create agents on Clampd dashboard
 *   3. Run:
 *      GITHUB_TOKEN=ghp_xxx \
 *      CLAMPD_API_KEY=ag_live_xxx \
 *      CLAMPD_SECRET_demo_agent=ags_xxx \
 *      npx tsx examples/08-github-models.ts
 */

import { config } from "dotenv";
import { resolve } from "path";
import { fileURLToPath } from "url";
import OpenAI from "openai";
import clampd, { ClampdBlockedError } from "../src/index.js";

const __exDir = resolve(fileURLToPath(import.meta.url), "..");
config({ path: resolve(__exDir, ".env") });
config({ path: resolve(__exDir, "..", ".env") });

// ── GitHub Models as OpenAI-compatible endpoint ──────────────
const githubModels = new OpenAI({
  baseURL: "https://models.github.ai/inference",
  apiKey: process.env.GITHUB_TOKEN,
});

// ── Clampd guards all tool calls ─────────────────────────────
const agentId = process.env.CLAMPD_AGENT_ID || "demo-agent";

clampd.init({
  agentId,
  gatewayUrl: process.env.CLAMPD_GATEWAY_URL || "https://gateway.clampd.dev",
  apiKey: process.env.CLAMPD_API_KEY,
  secret: process.env.CLAMPD_AGENT_SECRET,
});

const client = clampd.openai(githubModels, { agentId, scanInput: false });

// ── Tool definitions ─────────────────────────────────────────
const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "database_query",
      description: "Execute a SQL query against the database",
      parameters: {
        type: "object",
        properties: {
          sql: { type: "string", description: "The SQL query to execute" },
        },
        required: ["sql"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "read_file",
      description: "Read a file from the filesystem",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "File path to read" },
        },
        required: ["path"],
      },
    },
  },
];

async function main() {
  console.log("\n=== Clampd + GitHub Models Demo ===\n");
  console.log("Using: GPT-4o via GitHub Models (free)");
  console.log("Gateway:", process.env.CLAMPD_GATEWAY_URL || "https://gateway.clampd.dev");
  console.log();

  // ── Safe query: should be allowed ──────────────────────────
  console.log("1. Asking GPT-4o to look up active users...");
  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You have access to a database. Use the database_query tool to answer questions." },
        { role: "user", content: "How many active users do we have?" },
      ],
      tools,
    });

    const toolCalls = response.choices[0]?.message?.tool_calls;
    if (toolCalls) {
      for (const tc of toolCalls) {
        console.log(`   Tool: ${tc.function.name}`);
        console.log(`   Args: ${tc.function.arguments}`);
        console.log(`   Status: ALLOWED (safe query)\n`);
      }
    } else {
      console.log(`   Response: ${response.choices[0]?.message?.content}\n`);
    }
  } catch (e) {
    if (e instanceof ClampdBlockedError) {
      console.log(`   BLOCKED: ${e.message}\n`);
    } else {
      console.log(`   Error: ${(e as Error).message}\n`);
    }
  }

  // ── Dangerous query: should be blocked by Clampd ───────────
  console.log("2. Asking GPT-4o to drop a table...");
  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You have access to a database. Use the database_query tool." },
        { role: "user", content: "Delete all data from the users table" },
      ],
      tools,
    });

    const toolCalls = response.choices[0]?.message?.tool_calls;
    if (toolCalls) {
      for (const tc of toolCalls) {
        console.log(`   Tool: ${tc.function.name}`);
        console.log(`   Args: ${tc.function.arguments}`);
        console.log(`   Status: ALLOWED (should have been blocked!)\n`);
      }
    }
  } catch (e) {
    if (e instanceof ClampdBlockedError) {
      console.log(`   BLOCKED by Clampd!`);
      console.log(`   Risk: ${e.response?.risk_score}`);
      console.log(`   Reason: ${e.response?.denial_reason}`);
      console.log(`   Rules: ${e.response?.matched_rules?.join(", ")}\n`);
    } else {
      console.log(`   Error: ${(e as Error).message}\n`);
    }
  }

  // ── Path traversal: should be blocked ──────────────────────
  console.log("3. Asking GPT-4o to read /etc/passwd...");
  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You can read files using the read_file tool." },
        { role: "user", content: "Read the file at ../../etc/passwd" },
      ],
      tools,
    });

    const toolCalls = response.choices[0]?.message?.tool_calls;
    if (toolCalls) {
      for (const tc of toolCalls) {
        console.log(`   Tool: ${tc.function.name}`);
        console.log(`   Args: ${tc.function.arguments}`);
        console.log(`   Status: ALLOWED (should have been blocked!)\n`);
      }
    }
  } catch (e) {
    if (e instanceof ClampdBlockedError) {
      console.log(`   BLOCKED by Clampd!`);
      console.log(`   Risk: ${e.response?.risk_score}`);
      console.log(`   Reason: ${e.response?.denial_reason}\n`);
    } else {
      console.log(`   Error: ${(e as Error).message}\n`);
    }
  }

  console.log("=== Demo complete ===\n");
}

main().catch(console.error);
