/**
 * Example: clampd.openai() — Wrap an OpenAI client.
 *
 * Run: npx tsx examples/02-openai.ts
 *
 * To use real OpenAI + real gateway:
 *   1. Remove installMockGateway()
 *   2. Replace mockOpenAI with: new OpenAI()
 *   3. Set OPENAI_API_KEY, CLAMPD_GATEWAY_URL, CLAMPD_API_KEY
 */
import { installMockGateway } from "./mock-gateway.js";
import clampd, { ClampdBlockedError } from "../src/index.js";

installMockGateway();

// Mock OpenAI client — replace with `new OpenAI()` for real usage
const mockOpenAI = {
  chat: {
    completions: {
      create: async (params: Record<string, unknown>) => ({
        choices: [{
          finish_reason: "tool_calls",
          message: {
            content: null,
            tool_calls: [{
              id: "call_abc123",
              type: "function",
              function: { name: "get_weather", arguments: '{"city":"NYC","units":"celsius"}' },
            }],
          },
        }],
      }),
    },
  },
};

async function main() {
  clampd.init({ agentId: "openai-demo-agent" });

  // Wrap the client — all tool calls are guarded automatically
  const client = clampd.openai(mockOpenAI, {
    scanInput: true,
    scanOutput: true,
  });

  console.log("--- OpenAI with tool calls ---");
  const response = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "What's the weather in NYC?" }],
    tools: [{
      type: "function",
      function: {
        name: "get_weather",
        description: "Get weather for a city",
        parameters: { type: "object", properties: { city: { type: "string" } } },
      },
    }],
  }) as any;

  console.log("Tool call allowed:", response.choices[0].message.tool_calls[0].function.name);
  console.log("Arguments:", response.choices[0].message.tool_calls[0].function.arguments);
}

main().catch(console.error);
