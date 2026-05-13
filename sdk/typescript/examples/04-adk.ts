/**
 * Example: clampd.adk() — Google ADK (Agent Development Kit) integration.
 *
 * Run: npx tsx examples/04-adk.ts
 *
 * To use with real Google ADK:
 *   1. Remove installMockGateway()
 *   2. Use the callbacks with your ADK Agent:
 *      const agent = new Agent({
 *        before_tool_callback: callbacks.beforeTool,
 *        after_tool_callback: callbacks.afterTool,
 *      });
 */
import { installMockGateway } from "./mock-gateway.js";
import clampd from "../src/index.js";

installMockGateway();

async function main() {
  clampd.init({ agentId: "adk-demo-agent" });

  // Get ADK callbacks — beforeTool + afterTool (with checkResponse)
  const callbacks = clampd.adk({
    checkResponse: true,
    failOpen: false,
  });

  // Simulate an allowed tool call
  console.log("--- Allowed tool call ---");
  const beforeResult = await callbacks.beforeTool("web_search", { query: "clampd docs" });
  console.log("beforeTool result:", beforeResult); // null = allowed

  if (!beforeResult) {
    // Simulate tool execution
    const toolOutput = { results: ["clampd.dev - Runtime security for AI agents"] };
    const afterResult = await callbacks.afterTool!("web_search", toolOutput);
    console.log("afterTool result:", afterResult); // null = allowed
  }

  // Simulate a blocked tool call
  console.log("\n--- Blocked tool call ---");
  const blockedResult = await callbacks.beforeTool("exec_shell", { cmd: "rm -rf /" });
  console.log("beforeTool result:", JSON.stringify(blockedResult));
  // { error: "Tool 'exec_shell' is blocked by security policy" }
}

main().catch(console.error);
