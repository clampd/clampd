# @clampd/sdk — TypeScript SDK

Runtime security for AI agents. Guard every tool call — OpenAI, Anthropic, LangChain.js — in 1 line. Prompt and response scanning enabled by default.

## Installation

```bash
npm install @clampd/sdk
```

## Quick Start

```typescript
import clampd from "@clampd/sdk";
import OpenAI from "openai";

// Configure once at startup
clampd.init({
  agentId: "my-agent",
  secret: "ags_...",              // from dashboard → Agent → Secret
  gatewayUrl: "http://localhost:8080",
  apiKey: "ag_live_...",
});

// Wrap your OpenAI client — done
const client = clampd.openai(new OpenAI());

// Use it exactly like before. Clampd intercepts every tool call.
const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Look up active users" }],
  tools: [...],
});
// Dangerous tool calls → blocked before execution
// Safe tool calls → proceed normally
// Prompts scanned before LLM, responses scanned after
```

## What's New in 0.5.0

- **Per-agent JWT identity** — each agent in a multi-agent system authenticates independently. Kill/rate-limit/EMA operate per-agent.
- **Streaming guard** — opt-in tool call interception for streaming responses (`guardStream: true`)
- **Circuit breaker & retry** — automatic retry with exponential backoff, circuit breaker for gateway failures
- **CrewAI, ADK, Vercel AI wrappers** — guard tool calls across all major frameworks
- **216 detection rules** with Aho-Corasick prefilter (22μs at 10K rules)

## Configuration

```typescript
// Option 1: Single agent (simple)
clampd.init({
  agentId: "my-agent",
  secret: "ags_...",               // from dashboard → Agent → Secret
  gatewayUrl: "http://localhost:8080",
  apiKey: "ag_live_...",
});

// Option 2: Multi-agent (per-agent identity)
clampd.init({
  agentId: "orchestrator",
  apiKey: "ag_live_...",
  agents: {
    "orchestrator": process.env.CLAMPD_SECRET_orchestrator,
    "research-agent": process.env.CLAMPD_SECRET_research_agent,
    "writer-agent": process.env.CLAMPD_SECRET_writer_agent,
  },
});

// Option 3: Environment variables
// CLAMPD_GATEWAY_URL=http://localhost:8080
// CLAMPD_API_KEY=ag_live_...
// CLAMPD_SECRET_orchestrator=ags_...
// CLAMPD_SECRET_research_agent=ags_...
```

## Anthropic / Claude

```typescript
import clampd from "@clampd/sdk";
import Anthropic from "@anthropic-ai/sdk";

clampd.init({ agentId: "my-agent", secret: "ags_..." });
const client = clampd.anthropic(new Anthropic());

const response = await client.messages.create({
  model: "claude-sonnet-4-20250514",
  max_tokens: 1024,
  messages: [{ role: "user", content: "..." }],
  tools: [...],
});
```

## Direct Guard (any function)

```typescript
import clampd from "@clampd/sdk";

clampd.init({ agentId: "my-agent", secret: "ags_..." });

const safeQuery = clampd.guard(runQuery, {
  toolName: "database.query",
});

// With response checking (opt-in)
const safeRead = clampd.guard(readFile, {
  toolName: "file_read",
  checkResponse: true,
});

await safeQuery("SELECT * FROM users");  // allowed
await safeQuery("DROP TABLE users");     // throws ClampdBlockedError
```

## Scanning Options

```typescript
// Defaults (v0.4.0+): scanInput=true, scanOutput=true
const client = clampd.openai(new OpenAI(), { agentId: "my-agent" });

// Opt out of scanning
const client = clampd.openai(new OpenAI(), {
  agentId: "my-agent",
  scanInput: false,   // skip prompt scanning
  scanOutput: false,  // skip response scanning
});
```

## Multi-Agent (A2A Delegation)

```typescript
import clampd from "@clampd/sdk";

// Each agent authenticates with its own secret.
// Delegation chains are tracked automatically via AsyncLocalStorage.
clampd.init({
  agentId: "orchestrator",
  apiKey: "ag_live_...",
  agents: {
    "orchestrator": process.env.CLAMPD_SECRET_orchestrator,
    "research-agent": process.env.CLAMPD_SECRET_research_agent,
  },
});

// research-agent gets its own JWT (sub=research-agent).
// Kill "research-agent" from dashboard → only this agent is blocked.
const search = clampd.guard(searchFn, {
  agentId: "research-agent",
  toolName: "web.search",
});
```

## Streaming Guard (opt-in)

```typescript
// Stream tool calls are guarded only when guardStream is enabled.
const client = clampd.openai(new OpenAI(), {
  agentId: "my-agent",
  guardStream: true,  // buffer + guard tool call chunks before release
});

const stream = await client.chat.completions.create({
  model: "gpt-4o",
  stream: true,
  tools: [...],
  messages: [{ role: "user", content: "..." }],
});
// Tool calls in the stream are buffered, guarded, then released.
// Text chunks pass through immediately with zero added latency.
```

## Tool Definitions Wrapper

```typescript
import clampd from "@clampd/sdk";

// Wrap OpenAI-style tool definitions
const safeTools = clampd.tools(myToolDefs, { agentId: "my-agent", secret: "ags_..." });
```

## Error Handling

```typescript
import { ClampdBlockedError } from "@clampd/sdk";

try {
  await safeQuery("DROP TABLE users");
} catch (e) {
  if (e instanceof ClampdBlockedError) {
    console.log(`Blocked: ${e.message}`);
    // e.response.risk_score, e.response.denial_reason
  }
}
```

## API Reference

| Function | Description |
|----------|-------------|
| `clampd.init(opts)` | Configure global client. `agents` for per-agent secrets. |
| `clampd.openai(client, opts?)` | Wrap OpenAI client. `guardStream: true` for streaming. |
| `clampd.anthropic(client, opts?)` | Wrap Anthropic client. `guardStream: true` for streaming. |
| `clampd.guard(fn, opts)` | Wrap any async function. `agentId` for per-agent identity. |
| `clampd.tools(defs, opts)` | Wrap OpenAI tool definitions |
| `clampd.agent(agentId, fn)` | Run function in agent's delegation scope |

## Requirements

- Node.js 18+
- A running [Clampd](https://clampd.dev) gateway

## License

BUSL-1.1
