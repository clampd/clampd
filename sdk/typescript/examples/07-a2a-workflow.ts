/**
 * Example: Advanced Agent-to-Agent (A2A) Workflow with Clampd Security
 *
 * This demo simulates a real multi-agent system where:
 *   - Orchestrator Agent coordinates the workflow
 *   - Research Agent searches for information
 *   - Analysis Agent processes and summarizes data
 *   - Writer Agent produces the final output
 *
 * clampd.agent() sets up the delegation scope automatically.
 * clampd.guard() handles per-tool-call delegation internally.
 * Developers don't need to touch withDelegation/getDelegation directly.
 *
 * Run: npx tsx examples/07-a2a-workflow.ts
 */
import { config } from "dotenv";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { installMockGateway } from "./mock-gateway.js";
import clampd, { ClampdBlockedError } from "../src/index.js";

// Load .env - check examples/ dir first, then project root
const __exDir = resolve(fileURLToPath(import.meta.url), "..");
config({ path: resolve(__exDir, ".env") });
config({ path: resolve(__exDir, "..", ".env") });

// Use mock gateway when env vars aren't set (local dev / quick try).
// Set CLAMPD_API_KEY to use the real gateway.
if (!process.env.CLAMPD_API_KEY) {
  installMockGateway();
}

const orchestratorId = process.env.ORCHESTRATOR_ID || "orchestrator";
const researcherId = process.env.RESEARCHER_ID || "research-agent";
const analysisId = process.env.ANALYSIS_ID || "analysis-agent";
const writerId = process.env.WRITER_ID || "writer-agent";

clampd.init({
  agentId: orchestratorId,
  gatewayUrl: process.env.CLAMPD_GATEWAY_URL || "https://gateway.clampd.dev",
  apiKey: process.env.CLAMPD_API_KEY || "mock",
  secret: process.env.CLAMPD_SECRET_orchestrator,
  agents: {
    [orchestratorId]: process.env.CLAMPD_SECRET_orchestrator,
    [researcherId]: process.env.CLAMPD_SECRET_research_agent,
    [analysisId]: process.env.CLAMPD_SECRET_analysis_agent,
    [writerId]: process.env.CLAMPD_SECRET_writer_agent,
  },


});

// ── Guarded tools - each has its own agentId ─────────────────────
// The SDK builds the delegation chain automatically:
//   orchestrator -> research-agent -> web.search
//   orchestrator -> analysis-agent -> data.analyze
//   etc.

const searchWeb = clampd.guard(
  async (params: { query: string }) => {
    console.log(`    [search] Searching: "${params.query}"`);
    return {
      results: [
        "Clampd: Runtime security for AI agents - clampd.dev",
        "AI Agent Security Best Practices - OWASP",
        "Tool Call Interception Patterns - arxiv.org",
      ],
    };
  },
  { agentId: researcherId, toolName: "http.fetch" },
);

const analyzeData = clampd.guard(
  async (params: { query: string }) => {
    console.log(`    [analyze] Analyzing data`);
    return {
      summary: "Runtime security is critical for AI agents. " +
        "Key approaches include tool call interception, prompt scanning, and delegation chain tracking.",
      confidence: "high",
    };
  },
  { agentId: analysisId, toolName: "database.query" },
);

const writeReport = clampd.guard(
  async (params: { path: string; content: string }) => {
    console.log(`    [write] Generating report: "${params.path}"`);
    return {
      report: `# AI Agent Security\n\n${params.content}\n`,
    };
  },
  { agentId: writerId, toolName: "filesystem.write", checkResponse: true },
);

const deleteFiles = clampd.guard(
  async (params: { path: string }) => `Deleted: ${params.path}`,
  { agentId: "rogue-agent", toolName: "shell.exec" },
);

// ── Orchestrator - just use clampd.agent() for the scope ─────────

async function main() {
  console.log("=== A2A Workflow Demo ===\n");

  // clampd.agent() sets up the delegation scope. That's it.
  // All guard() calls inside inherit the chain automatically.
  await clampd.agent(process.env.ORCHESTRATOR_ID || "orchestrator-agent", async () => {

    // Step 1: Research
    console.log("Step 1: Research Agent");
    const { results: sources } = await searchWeb({ query: "AI agent security" });
    console.log(`  Found ${sources.length} sources\n`);

    // Step 2: Analysis
    console.log("Step 2: Analysis Agent");
    const { summary, confidence } = await analyzeData({ query: "SELECT summary FROM research WHERE topic = 'AI agent security'" });
    console.log(`  Confidence: ${confidence}\n`);

    // Step 3: Writing
    console.log("Step 3: Writer Agent");
    const { report } = await writeReport({ path: "/reports/ai-security.md", content: summary });
    console.log("  Report generated\n");

    // Step 4: Blocked dangerous action
    console.log("Step 4: Rogue agent tries to delete files...");
    try {
      await deleteFiles({ path: "/important-data" });
    } catch (err) {
      if (err instanceof ClampdBlockedError) {
        console.log("  BLOCKED by Clampd!");
        console.log(`  Reason: ${err.response.denial_reason}`);
        console.log(`  Risk: ${err.response.risk_score}\n`);
      }
    }

    console.log("=== Final Report ===\n");
    console.log(report);
  });
}

main().catch(console.error);
