# @clampd/sdk — TypeScript SDK

Runtime security for AI agents. Guard every tool call — OpenAI, Anthropic, LangChain.js — in 1 line. Prompt and response scanning enabled by default.

## Installation

```bash
npm install @clampd/sdk
```

## Quick Start

One connection string, no agent IDs, no secrets to manage. Set your DSN
once — the SDK enrolls the agent itself on first use (generates an Ed25519
keypair, registers, and keeps the private key local):

```bash
export CLAMPD_DSN=clampd://ag_live_...@gateway.clampd.dev
```

```typescript
import clampd from "@clampd/sdk";
import OpenAI from "openai";

await clampd.init();                  // reads CLAMPD_DSN, enrolls automatically

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

### Zero code: `clampd run`

Don't want to touch your code at all? Launch any program through the CLI.
It auto-initializes from `CLAMPD_DSN` and transparently guards every OpenAI /
Anthropic client your program constructs — no `clampd.init()`, no
`clampd.openai(...)` wrapping:

```bash
export CLAMPD_DSN=clampd://ag_live_...@gateway.clampd.dev
clampd run -- node app.js
clampd run -- tsx server.ts
```

Prefer a one-liner in code instead of the launcher? A single import does the
same thing (auto-init + auto-wrap), as long as it runs before you construct
your LLM clients:

```typescript
import "@clampd/sdk/auto";   // auto-inits from CLAMPD_DSN and patches openai/anthropic
```

## What's New in 0.23.3

When Clampd blocks a tool call, it hands the LLM a structured hint
the model can pattern-match on instead of a free-text "denied" string.
0.23.3 is the cleanup: every corrective comes from a rule or policy,
no code-side overrides, no synthesized fallbacks.

- **Rule-only correctives.** The SDK no longer ships a `suggest`
  option on `wrapFunction`. Every corrective comes from a rule's
  `[rule.corrective]` block or a Cedar `@corrective_*` annotation,
  which means security policy lives in the admin surface, not in
  tool-author code.

- **Honest fallbacks.** When no source authors a corrective, denials
  emit `kind = "noCorrection"` with rule attribution rather than a
  synthesized scope-mismatch hint that may be semantically wrong
  (the old "tool requires X / Permitted: X / Closest: X" bug is gone).

- **`requestApproval` variant removed** from the public surface
  until admin approval routing is built. The proto wire shape keeps
  the variant for backwards compat; SDKs simply don't emit or parse
  it any more.

- **Typed corrective actions.** Denials carry one of **9 variant
  shapes** (`switchTool`, `downscopeTo`, `renameField`, `redactValue`,
  `splitRequest`, `waitAndRetry`, `switchEndpoint`, `noCorrection`,
  plus `downscopeAuto` for resolver-picked alternatives). Read
  `error.denial.corrective` for the typed shape; call
  `error.toToolResult()` for the ready-to-send string.

- **`ClampdLoopError`.** When an LLM keeps retrying the same denied
  call (idempotency key seen three times in a row), this is thrown
  instead of another `ClampdBlockedError`. Catch it first so loop
  detection isn't swallowed.

- **`clampd.registerTool()`.** Declare each tool's category at
  startup. Bypasses default-deny on first use and locks the descriptor
  hash so rug-pull detection has a baseline.

- **Bard-quality messages.** Every denial reads
  ``Action blocked: X. Reformulate the call under scope `Y`.`` The
  next step lives in backticks where the LLM can grab it cleanly.

- **Silent on attacks.** Prompt-injection, command-injection, RCE,
  SSRF, path-traversal and ~180 other detection rules now emit
  `kind = "noCorrection"` with an empty hint, so the LLM-facing
  string is the bare phrase `"Action blocked."` — nothing for an
  attacker to iterate on. The dashboard chip still renders for
  operator visibility.

## What's New in 0.5.0

- **Per-agent JWT identity** — each agent in a multi-agent system authenticates independently. Kill/rate-limit/EMA operate per-agent.
- **Streaming guard** — opt-in tool call interception for streaming responses (`guardStream: true`)
- **Circuit breaker & retry** — automatic retry with exponential backoff, circuit breaker for gateway failures
- **CrewAI, ADK, Vercel AI wrappers** — guard tool calls across all major frameworks
- **216 detection rules** with Aho-Corasick prefilter (22μs at 10K rules)

## Configuration

A single DSN is all the configuration there is. It carries both the gateway
host and your org's publishable key:

```
clampd://<org_key>@<host>          // TLS (default)
clampd+http://<org_key>@<host>     // plaintext, for local dev
```

```typescript
// From the environment (recommended) — set CLAMPD_DSN, then:
await clampd.init();

// ...or pass it explicitly:
await clampd.init({ dsn: "clampd://ag_live_...@gateway.clampd.dev" });

// Give the agent a stable logical name (otherwise the hostname / process
// name is used). The gateway assigns the UUID at enrollment.
await clampd.init({ name: "research-agent" });
```

There are no secrets to distribute or rotate: each agent generates its own
Ed25519 keypair on first run, registers the public key with the gateway, and
signs requests locally. The private key never leaves the machine.

> `clampd.init()` is async (enrollment hits the gateway) — `await` it before
> your first guarded call, or use the zero-code paths above which handle that
> for you.

## Anthropic / Claude

```typescript
import clampd from "@clampd/sdk";
import Anthropic from "@anthropic-ai/sdk";

await clampd.init();
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

await clampd.init();

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

## Tool Registration (recommended at startup)

Declare each tool's category once. Tools registered this way bypass
default-deny on first use and lock the descriptor hash so rug-pull
detection has a baseline.

```typescript
import clampd, { Category, Subcategory, Operation } from "@clampd/sdk";

await clampd.init();

await clampd.registerTool("database.query", {
  category: Category.DB,
  subcategory: Subcategory.QUERY,
  operation: Operation.READ,
  description: "Read-only SQL against the analytics DB.",
});
```

## How corrective hints get to the LLM

You don't have to do anything. When a tool call gets denied, Clampd
returns a typed hint (`switchTool → archive_table`, `waitAndRetry`,
etc.) that the LLM can pattern-match on. The hint comes from whichever
source matched first:

```
boundary > sdk_override > cedar > per-agent > rule template > downscope_auto
```

For most rules this is already wired. R001 (destructive SQL) for
example ships with a `switchTool` corrective pointing at
`archive_table`. When the LLM hits that, it sees:

```
Action blocked: Destructive SQL (DROP/TRUNCATE/DELETE) is blocked.
Use archive_table to soft-delete (archived=true column).
Reformulate this call using the `archive_table` tool instead.
```

It pattern-matches on `` `archive_table` `` and pivots on the next turn.

**Authoring is now the only path.** As of v0.23.3 Clampd no longer
accepts code-side corrective overrides via the SDK. Correctives must be
authored on the rule (via TOML or the dashboard) or on the Cedar policy.
This puts security policy where it belongs — under admin review — and
removes a class of override that bypassed the audit trail.

### Authoring custom correctives

The recommended path is the **dashboard**. Two ways:

1. **Cedar policy with `@corrective_*` annotations.** Author once,
   covers every agent in the org.
2. **Per-agent override** on the rules page. Useful when one agent
   needs a different remedy than the org default.

Both ship in 0.23.0+ via the Policies / Agents UI.

Valid `kind` values: `switch_tool`, `downscope_to`, `downscope_auto`,
`rename_field`, `redact_value`, `split_request`, `wait_and_retry`,
`switch_endpoint`, `no_correction`.

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

await clampd.init();

// Name an agent at the call site and the SDK enrolls it on demand — each
// logical name gets its own Ed25519 identity (sub=research-agent), no secrets
// to wire up. Delegation chains are tracked automatically via AsyncLocalStorage.
//
// Kill "research-agent" from the dashboard → only this agent is blocked.
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
const safeTools = clampd.tools(myToolDefs, { agentId: "my-agent" });
```

## Error Handling

As of v0.20+ blocked tool calls carry a typed `StructuredDenial` with a
corrective action the LLM can pattern-match on. Catch `ClampdLoopError`
*before* `ClampdBlockedError` so legitimate loop detection isn't swallowed
by the more general handler.

```typescript
import { ClampdBlockedError, ClampdLoopError } from "@clampd/sdk";

try {
  await safeQuery("DROP TABLE users");
} catch (e) {
  if (e instanceof ClampdLoopError) {
    // The LLM has retried the same denied call too many times.
    // Surface as a hard error — don't feed back to the model.
    throw e;
  }
  if (e instanceof ClampdBlockedError) {
    // Hand the gateway-rendered string back to the LLM tool loop —
    // the model will pattern-match on the backticked tool / scope.
    const toolResultContent = e.toToolResult();
    // Or inspect the typed corrective directly:
    const c = e.denial?.corrective;
    if (c?.action.kind === "switchTool") {
      // Auto-retry with the safer tool
      await retryWith(c.action.tool);
    }
  }
}
```

`error.denial` is `StructuredDenial | null` carrying:
- `ruleId` — the rule or `NEVER_EXEMPTABLE` predicate that fired
- `violatedPredicate` — human-readable WHY (e.g. "Destructive SQL blocked")
- `corrective` — typed `CorrectiveAction` or `null`
- `idempotencyKey` — stable hash so the SDK can detect loops
- `reasonCodes`, `boundaryViolation`

`error.toToolResult()` returns the gateway's pre-rendered string ready
to drop into `tool_result.content` — same text the dashboard chip shows,
no client-side template logic.

## API Reference

| Function | Description |
|----------|-------------|
| `clampd.init(opts?)` | Async. Configure from a DSN (or `CLAMPD_DSN`) and auto-enroll. `{ name }` sets the agent's logical name. |
| `import "@clampd/sdk/auto"` / `clampd run -- <cmd>` | Zero-code: auto-init from `CLAMPD_DSN` + auto-wrap OpenAI/Anthropic clients. |
| `clampd.registerTool(name, { category, subcategory, operation, ... })` | Declare a tool's taxonomy classification at startup. Bypasses default-deny on first use. |
| `clampd.openai(client, opts?)` | Wrap OpenAI client. `guardStream: true` for streaming. |
| `clampd.anthropic(client, opts?)` | Wrap Anthropic client. `guardStream: true` for streaming. |
| `clampd.guard(fn, opts)` / `wrapFunction(fn, opts)` | Wrap any async function. |
| `clampd.tools(defs, opts)` | Wrap OpenAI tool definitions. |
| `clampd.agent(agentId, fn)` | Run function in agent's delegation scope. |
| `Category` / `Subcategory` / `Operation` | Taxonomy enums for `registerTool`. |
| `ClampdBlockedError` / `ClampdLoopError` | Typed exception hierarchy. |

## Requirements

- Node.js 18+
- A running [Clampd](https://clampd.dev) gateway

## License

BUSL-1.1
