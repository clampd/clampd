/**
 * Example: clampd.guard() - Wrap any async function with security.
 *
 * Run: npx tsx examples/01-guard.ts
 *
 * To use a real gateway, remove the mock and set:
 *   CLAMPD_GATEWAY_URL=http://localhost:8080
 *   CLAMPD_API_KEY=your-key
 */
import { installMockGateway } from "./mock-gateway.js";
import clampd, { ClampdBlockedError } from "../src/index.js";

installMockGateway();

clampd.init({ agentId: "guard-demo-agent" });

// Your original tool function
async function queryDatabase(params: { sql: string }): Promise<string> {
  return `Results for: ${params.sql}`;
}

// Wrap it - every call is now guarded
const safeQuery = clampd.guard(queryDatabase, {
  toolName: "db.query",
  checkResponse: true,
});

async function main() {
  // Allowed call
  console.log("--- Safe query ---");
  const result = await safeQuery({ sql: "SELECT name FROM users LIMIT 10" });
  console.log("Result:", result);

  // Blocked call (drop_table is in the blocked list)
  console.log("\n--- Dangerous query ---");
  const dangerousQuery = clampd.guard(
    async (p: { table: string }) => `dropped ${p.table}`,
    { toolName: "drop_table" },
  );

  try {
    await dangerousQuery({ table: "users" });
  } catch (err) {
    if (err instanceof ClampdBlockedError) {
      console.log("BLOCKED!");
      console.log("  Reason:", err.response.denial_reason);
      console.log("  Risk:", err.response.risk_score);
      console.log("  Rules:", err.matchedRules);
    }
  }
}

main().catch(console.error);
