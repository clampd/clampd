/**
 * Example: clampd.anthropic() - Wrap an Anthropic/Claude client.
 *
 * Run: npx tsx examples/03-anthropic.ts
 *
 * To use real Anthropic + real gateway:
 *   1. Remove installMockGateway()
 *   2. Replace mockAnthropic with: new Anthropic()
 *   3. Set ANTHROPIC_API_KEY, CLAMPD_GATEWAY_URL, CLAMPD_API_KEY
 */
import { installMockGateway } from "./mock-gateway.js";
import clampd from "../src/index.js";

installMockGateway();

// Mock Anthropic client - replace with `new Anthropic()` for real usage
const mockAnthropic = {
  messages: {
    create: async (params: Record<string, unknown>) => ({
      id: "msg_mock",
      type: "message",
      role: "assistant",
      stop_reason: "tool_use",
      content: [
        { type: "text", text: "I'll search that for you." },
        { type: "tool_use", id: "toolu_01", name: "web_search", input: { query: "clampd security" } },
      ],
    }),
  },
};

async function main() {
  clampd.init({ agentId: "anthropic-demo-agent" });

  const client = clampd.anthropic(mockAnthropic, {
    scanInput: true,
    scanOutput: true,
  });

  console.log("--- Anthropic with tool_use ---");
  const response = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 1024,
    messages: [{ role: "user", content: "Search for clampd security SDK" }],
    tools: [{
      name: "web_search",
      description: "Search the web",
      input_schema: { type: "object", properties: { query: { type: "string" } } },
    }],
  }) as any;

  for (const block of response.content) {
    if (block.type === "text") console.log("Text:", block.text);
    if (block.type === "tool_use") console.log("Tool use:", block.name, "->", JSON.stringify(block.input));
  }
}

main().catch(console.error);
