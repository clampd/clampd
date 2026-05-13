/**
 * Example: clampd.vercelAI() — Vercel AI SDK integration.
 *
 * Run: npx tsx examples/05-vercel-ai.ts
 *
 * To use with real Vercel AI SDK:
 *   1. Remove installMockGateway()
 *   2. Import { tool } from "ai" and define real tools
 *   3. Use safeTools with generateText() or streamText()
 */
import { installMockGateway } from "./mock-gateway.js";
import clampd, { ClampdBlockedError } from "../src/index.js";

installMockGateway();

async function main() {
  clampd.init({ agentId: "vercel-ai-demo-agent" });

  // Define Vercel AI-style tools (object with execute functions)
  const myTools = {
    getWeather: {
      description: "Get weather for a city",
      parameters: { type: "object", properties: { city: { type: "string" } } },
      execute: async (args: Record<string, unknown>) => {
        return { temperature: 72, condition: "sunny", city: args.city };
      },
    },
    sendEmail: {
      description: "Send an email",
      parameters: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } },
      execute: async (args: Record<string, unknown>) => {
        return { sent: true, to: args.to };
      },
    },
  };

  // Wrap all tools — execute functions are now guarded
  const safeTools = clampd.vercelAI(myTools, {});

  // Call an allowed tool
  console.log("--- Allowed: getWeather ---");
  const weather = await safeTools.getWeather.execute!({ city: "NYC" });
  console.log("Result:", weather);

  // Call another allowed tool
  console.log("\n--- Allowed: sendEmail ---");
  const email = await safeTools.sendEmail.execute!({ to: "user@test.com", body: "Hello!" });
  console.log("Result:", email);

  // Demonstrate that tool properties are preserved
  console.log("\n--- Tool properties preserved ---");
  console.log("getWeather.description:", safeTools.getWeather.description);
  console.log("sendEmail.description:", safeTools.sendEmail.description);
}

main().catch(console.error);
