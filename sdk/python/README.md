# Clampd Python SDK

Runtime security for AI agents. Guard every tool call — OpenAI, Anthropic, LangChain, Google ADK — in 1 line. Prompt and response scanning enabled by default.

## Installation

```bash
pip install clampd
```

With framework extras:

```bash
pip install clampd[langchain]    # LangChain callback handler
pip install clampd[mcp]          # MCP server support
pip install clampd[all]          # Everything
```

## Quick Start

One connection string, no agent IDs, no secrets to manage. Set your DSN
once — the SDK enrolls the agent itself on first use (generates an Ed25519
keypair, registers, and keeps the private key local):

```bash
export CLAMPD_DSN=clampd://ag_live_...@gateway.clampd.dev
```

```python
import clampd
from openai import OpenAI

clampd.init()                       # reads CLAMPD_DSN, enrolls automatically

# Wrap your OpenAI client — done
client = clampd.openai(OpenAI())

# Use it exactly like before. Clampd intercepts every tool call.
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Look up active users"}],
    tools=[...],
)
# Dangerous tool calls → blocked before execution
# Safe tool calls → proceed normally
# Prompts scanned before LLM, responses scanned after
```

### Zero code: `clampd run`

Don't want to touch your code at all? Launch any program through the CLI.
It auto-initializes from `CLAMPD_DSN` and transparently guards every OpenAI /
Anthropic client your program constructs — no `clampd.init()`, no
`clampd.openai(...)` wrapping:

```bash
export CLAMPD_DSN=clampd://ag_live_...@gateway.clampd.dev
clampd run -- python app.py
clampd run -- uvicorn main:app
```

Prefer a one-liner in code instead of the launcher? A single import does the
same thing (auto-init + auto-wrap), as long as it runs before you construct
your LLM clients:

```python
import clampd.auto      # auto-inits from CLAMPD_DSN and patches openai/anthropic
```

## What's New (latest)

- **Workload identity attestation (OIDC / k8s).** In production, an agent can
  enroll by presenting its platform identity token (a Kubernetes ServiceAccount
  token or any OIDC `id_token`) instead of a shared token. The gateway verifies
  it offline against the issuer's published JWKS and derives a **stable identity**
  from the token's `sub`, so the same workload keeps the same agent across pod
  restarts and key rotation. Zero code — auto-detected from the projected token.
- **Idempotent auto-recovery.** A workload that lost its local key re-presents
  its platform identity and gets **rebound to the same agent UUID** automatically.
- **Kill-by-attestation.** Killing an agent with a workload identity revokes that
  identity — a re-enroll with the same `sub` is refused (`403 enrollment_refused`)
  until an admin re-keys. You kill the workload, not just one row.
- **Re-key recovery.** Lost the local key with no platform identity? Mint a
  one-time re-key token in the dashboard and set `CLAMPD_REBIND_TOKEN` — a fresh
  keypair is bound to the **same agent UUID**, history preserved.
- **Tool catalog is the source of truth.** Tool → scope is owned in the dashboard
  (declare / approve / bulk-approve), not in code. You never wire tool→scope; the
  gateway resolves it from the catalog, the SQL effect (deterministic), or marks
  the tool unclassified (still scanned, default-denied if risky). `register_tool()`
  is optional pre-declaration.

## What's New in 0.23.3

When Clampd blocks a tool call, it hands the LLM a structured hint
the model can pattern-match on instead of a free-text "denied" string.
0.23.3 is the cleanup: every corrective comes from a rule or policy,
no code-side overrides, no synthesized fallbacks.

- **Rule-only correctives.** The SDK no longer ships a `suggest=`
  kwarg. Every corrective comes from a rule's `[rule.corrective]`
  block or a Cedar `@corrective_*` annotation, which means security
  policy lives in the admin surface, not in tool-author code.

- **Honest fallbacks.** When no source authors a corrective, denials
  emit `kind = "no_correction"` with rule attribution rather than a
  synthesized scope-mismatch hint that may be semantically wrong (the
  old "tool requires X / Permitted: X / Closest: X" bug is gone).

- **`request_approval` variant removed** from the public surface
  until admin approval routing is built. The proto wire shape keeps
  the variant for backwards compat; SDKs simply don't emit or parse
  it any more.

- **Typed corrective actions.** Denials carry one of **9 variant
  shapes** (`switch_tool`, `downscope_to`, `rename_field`,
  `redact_value`, `split_request`, `wait_and_retry`, `switch_endpoint`,
  `no_correction`, plus `downscope_auto` for resolver-picked
  alternatives). Read `error.denial.corrective` for the typed shape;
  call `error.to_tool_result()` for the ready-to-send string.

- **`ClampdLoopError`.** When an LLM keeps retrying the same denied
  call (idempotency key seen three times in a row), this is raised
  instead of another `ClampdBlockedError`. Catch it first so loop
  detection isn't swallowed.

- **`clampd.register_tool()`.** Declare each tool's category at
  startup. Bypasses default-deny on first use and locks the descriptor
  hash so rug-pull detection has a baseline.

- **Bard-quality messages.** Every denial reads
  ``Action blocked: X. Reformulate the call under scope `Y`.`` The
  next step lives in backticks where the LLM can grab it cleanly.

- **Silent on attacks.** Prompt-injection, command-injection, RCE,
  SSRF, path-traversal and ~180 other detection rules now emit
  `kind = "no_correction"` with an empty hint, so the LLM-facing
  string is the bare phrase `"Action blocked."` — nothing for an
  attacker to iterate on. The dashboard chip still renders for
  operator visibility.

## What's New in 0.5.0

- **Per-agent JWT identity** — each agent authenticates independently in multi-agent systems
- **Streaming guard** — opt-in tool call interception for streaming responses (`guard_stream=True`)
- **Circuit breaker & retry** — automatic retry with exponential backoff
- **CrewAI integration** — guard CrewAI agent tool calls
- **216 detection rules** with Aho-Corasick prefilter (22μs at 10K rules)

## Configuration

A single DSN is all the configuration there is. It carries both the gateway
host and your org's publishable key:

```
clampd://<org_key>@<host>          # TLS (default)
clampd+http://<org_key>@<host>     # plaintext, for local dev
```

```python
# From the environment (recommended) — set CLAMPD_DSN, then:
clampd.init()

# ...or pass it explicitly:
clampd.init("clampd://ag_live_...@gateway.clampd.dev")

# Give the agent a stable logical name (otherwise the hostname / process
# name is used). The gateway assigns the UUID at enrollment.
clampd.init(name="research-agent")
```

There are no secrets to distribute or rotate: each agent generates its own
Ed25519 keypair on first run, registers the public key with the gateway, and
signs requests locally. The private key never leaves the machine.

### Enrollment attestation

Self-enrollment is gated by an attestation so not anyone with the org key can
register an agent. Pick one per environment — the SDK tries them in this order:

| Env var (or source) | Mode | Use |
|---------------------|------|-----|
| `CLAMPD_REBIND_TOKEN=crt_...` | re-key | recover a lost-key agent → **same UUID** |
| `CLAMPD_ENROLL_TOKEN=cet_...` | enroll token | org-wide token for scaled fleets / CI |
| *(projected workload token)* | **oidc** | production k8s/OIDC identity → stable `sub` |
| *(none)* | open | dev only; gateway-gated by `CLAMPD_ALLOW_OPEN_ENROLLMENT` |

Mint `cet_` / `crt_` tokens and register trusted OIDC issuers in the dashboard.

**Workload OIDC** is auto-detected — no env var needed if a projected token is
present. Discovery order:

```bash
CLAMPD_WORKLOAD_TOKEN=<raw token>                          # explicit override
CLAMPD_WORKLOAD_TOKEN_FILE=/path/to/token                  # explicit file
# else: /var/run/secrets/clampd.io/token
# else: /var/run/secrets/kubernetes.io/serviceaccount/token
```

Project a token with audience `clampd` and register the issuer once in
**Settings → Workload Identity**; the gateway verifies it and binds the agent to
`<issuer>:<sub>`. See `services/docs/ARCHITECTURE.md` for the full flow.

### Tool classification (no code)

You don't classify tools in code. The dashboard **tool catalog** owns
tool → scope: admins declare or approve each tool once, and all agents inherit
it. Unknown tools are still scanned and default-denied if risky, and surface in
the dashboard for classification (auto-approved while Learning Mode is on).
`clampd.register_tool()` is an optional way to pre-declare a tool's category at
startup.

## Anthropic / Claude

```python
import clampd
from anthropic import Anthropic

clampd.init()
client = clampd.anthropic(Anthropic())

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "..."}],
    tools=[...],
)
```

## LangChain

```python
import clampd

clampd.init()
handler = clampd.langchain(agent_id="my-agent")

result = executor.invoke(
    {"input": "Look up active users"},
    config={"callbacks": [handler]},
)
```

## Google ADK

```python
import clampd
from google.adk import Agent

agent = Agent(
    tools=[...],
    before_tool_callback=clampd.adk(agent_id="my-agent"),
)
```

## Multi-Agent (A2A Delegation)

Each agent gets its own identity by **naming it** — the SDK enrolls each logical
name on demand (its own Ed25519 keypair, `sub=research-agent`), no secrets to
wire. Per-agent `allowed_scopes` are set once in the dashboard, so a compromised
writer can't touch the DB and a read-only researcher can't mutate.

`clampd.agent(name)` opens a **delegation scope**: every guarded call inside
inherits the chain automatically (via `contextvars`), and the SDK signs the
`(leaf, chain)` proof with the agent's Ed25519 key. **In-process delegation is
automatic — you do not pass any headers.**

```python
import clampd

clampd.init()

@clampd.guard("web.search", agent_id="research-agent")
def search(query: str):
    return web_search(query)

# The orchestrator delegates to research-agent. The chain
# orchestrator → research-agent is tracked + signed automatically.
with clampd.agent("orchestrator"):
    results = search("EU signups last quarter")

# Kill "research-agent" from the dashboard → only that agent is blocked.
# Contagion / cycle detection fires if an agent is pulled off its declared surface.
```

### LangGraph (supervisor + workers)

```python
import clampd
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool

clampd.init()  # one CLAMPD_DSN for the whole process

@tool
def db_query(sql: str) -> str:
    """Read-only analytics query."""        # SQL effect → db:query:read
    ...

@tool
def web_search(query: str) -> str:
    """Search the web."""                    # classify once in the dashboard
    ...

def llm_for(name: str, tools=None):
    # clampd.langchain(agent_id=name) guards every tool call this LLM makes,
    # under that agent's identity + scopes.
    llm = ChatOpenAI(model="gpt-4o").bind_tools(tools or [])
    return llm, clampd.langchain(agent_id=name)

class S(TypedDict):
    task: str
    research: str
    draft: str

def supervisor(state: S) -> S:
    llm, cb = llm_for("supervisor")          # delegation-only; no tool scope
    # ... decide route ...
    return state

def researcher(state: S) -> S:
    llm, cb = llm_for("researcher", [db_query, web_search])
    with clampd.agent("supervisor"):         # chain: supervisor → researcher (auto)
        out = llm.invoke([HumanMessage(content=f"Research: {state['task']}")],
                         config={"callbacks": [cb]})
    return {"research": out.content}

def writer(state: S) -> S:
    llm, cb = llm_for("writer")              # no external tools
    with clampd.agent("supervisor"):         # chain: supervisor → writer (auto)
        out = llm.invoke([HumanMessage(content=f"Write: {state['task']}\n{state['research']}")],
                         config={"callbacks": [cb]})
    return {"draft": out.content}

g = StateGraph(S)
g.add_node("supervisor", supervisor); g.add_node("researcher", researcher); g.add_node("writer", writer)
g.add_edge(START, "supervisor"); g.add_edge("supervisor", "researcher")
g.add_edge("researcher", "writer"); g.add_edge("writer", END)
app = g.compile()

print(app.invoke({"task": "How many EU customers signed up last quarter?"})["draft"])
```

You wire **no tool→scope and no delegation headers** in code. The dashboard
catalog owns tool→scope; delegation is carried by the `contextvars` chain.

### Cross-process / microservices

When agent A's process calls agent B's **separate HTTP service**, the
`contextvars` chain can't cross the boundary — attach it as headers:

```python
import requests, clampd

with clampd.agent("orchestrator"):
    # delegation_headers() serializes the current chain for the outbound hop
    requests.post(other_service_url, headers=clampd.delegation_headers(), json=payload)
```

The receiving service's guarded calls then continue the same chain.

## Public API

| Function | Purpose |
|----------|---------|
| `clampd.init(dsn=None, name=None)` | Read `CLAMPD_DSN`, prepare auto-enrollment. Call once. |
| `clampd.openai(client, agent_id=None, guard_stream=True)` | Wrap an OpenAI client; guards every tool call. |
| `clampd.anthropic(client, agent_id=None)` | Wrap an Anthropic client. |
| `clampd.langchain(*, agent_id=None, target_url="", fail_open=False, check_response=False)` | LangChain callback handler that guards tool calls. |
| `clampd.adk(*, agent_id=None)` | Google ADK `before_tool_callback`. |
| `clampd.crewai(*, agent_id=None, check_response=False)` | CrewAI tool guard. |
| `clampd.guard(tool_name, agent_id=None)` | Decorator to guard any function as a named tool. |
| `clampd.agent(name)` | Decorator/`with` context that opens a delegation scope; inner guarded calls inherit + sign the chain. |
| `clampd.delegation_headers() -> dict` | Serialize the current delegation chain into HTTP headers (cross-process only). |
| `clampd.register_tool(tool_or_name, category, subcategory, operation, description="")` | Optional: pre-declare a tool's classification at startup. |
| `clampd.require_scope(...)` / `verify_scope_token(...)` / `verify_call_binding(...)` | Tool-side scope-token verification (#5 call-binding). |

Errors: `ClampdBlockedError`, `ClampdClassificationError`,
`ClampdDescriptorMismatchError` (rug-pull), `ClampdLoopError`,
`ClampdUnregisteredToolError`, `ScopeVerificationError`.


## Streaming Guard (opt-in)

```python
# Stream tool calls are guarded only when guard_stream is enabled.
client = clampd.openai(OpenAI(),
    agent_id="my-agent",
    guard_stream=True,  # buffer + guard tool call chunks before release
)

stream = client.chat.completions.create(
    model="gpt-4o",
    stream=True,
    tools=[...],
    messages=[{"role": "user", "content": "..."}],
)
# Tool calls in the stream are buffered, guarded, then released.
# Text chunks pass through immediately with zero added latency.
```

## CrewAI

```python
import clampd
from clampd.crewai_callback import ClampdCrewAIGuard

clampd.init()
guard = ClampdCrewAIGuard()

# Wrap CrewAI tools
safe_tool = guard.wrap_tool(my_tool)
```

## Direct Guard (any function)

```python
import clampd

clampd.init()

@clampd.guard("database.query")
def run_query(sql: str):
    return db.execute(sql)

# With response checking (opt-in)
@clampd.guard("file_read", check_response=True)
def read_file(path: str):
    return open(path).read()

run_query("SELECT * FROM users")     # allowed
run_query("DROP TABLE users")        # raises ClampdBlockedError
```

## Tool Registration (recommended at startup)

Declare each tool's category once. Tools registered this way bypass
default-deny on first use and lock their descriptor hash so rug-pull
detection has a baseline to compare against.

```python
import clampd

clampd.init()

# Declare tool classification once at startup
clampd.register_tool(
    "database.query",
    category=clampd.Category.DB,
    subcategory=clampd.Subcategory.QUERY,
    operation=clampd.Operation.READ,
    description="Read-only SQL against the analytics DB.",
)

@clampd.guard("database.query")
def database_query(sql: str): ...
```

You can also pass a framework tool object directly — LangChain
`BaseTool`, OpenAI tool dict, or Anthropic tool dict — and Clampd
extracts the name and schema.

## How corrective hints get to the LLM

You don't have to do anything. When a tool call gets denied, Clampd
returns a typed hint (`switch_tool → archive_table`, `wait_and_retry`,
etc.) that the LLM can pattern-match on. The hint comes from whichever
source matched first:

```
boundary > sdk_override > cedar > per-agent > rule template > downscope_auto
```

For most rules this is already wired. R001 (destructive SQL) for
example ships with a `switch_tool` corrective pointing at
`archive_table`. When the LLM hits that, it sees:

```
Action blocked: Destructive SQL (DROP/TRUNCATE/DELETE) is blocked.
Use archive_table to soft-delete (archived=true column).
Reformulate this call using the `archive_table` tool instead.
```

It pattern-matches on `` `archive_table` `` and pivots on the next turn.

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

**Authoring is now the only path.** As of v0.23.3 Clampd no longer
accepts code-side corrective overrides via the SDK. Correctives must be
authored on the rule (via TOML or the dashboard) or on the Cedar policy.
This puts security policy where it belongs — under admin review — and
removes a class of override that bypassed the audit trail.

## Scanning Options

```python
# Defaults (v0.4.0+): scan_input=True, scan_output=True
client = clampd.openai(OpenAI(), agent_id="my-agent")

# Opt out of scanning
client = clampd.openai(OpenAI(),
    agent_id="my-agent",
    scan_input=False,   # skip prompt scanning
    scan_output=False,  # skip response scanning
)
```

## Error Handling

As of v0.20+, blocked tool calls carry a typed `StructuredDenial` with a
corrective action the LLM can pattern-match on. Catch `ClampdLoopError`
*before* `ClampdBlockedError` so legitimate loop detection isn't swallowed
by the more general handler.

```python
from clampd import ClampdBlockedError, ClampdLoopError

try:
    run_query("DROP TABLE users")
except ClampdLoopError as e:
    # The LLM has retried the same denied call too many times.
    # Surface as a hard error — don't feed back to the model.
    raise
except ClampdBlockedError as e:
    # Hand the gateway-rendered string back to the LLM tool loop —
    # the model will pattern-match on the backticked tool / scope.
    tool_result_content = e.to_tool_result()
    # Or inspect the typed corrective directly:
    if e.denial and e.denial.corrective:
        c = e.denial.corrective
        match c.action:
            case clampd._corrective.SwitchTool(tool=t):
                # Auto-retry with the safer tool
                ...
            case clampd._corrective.WaitAndRetry(retry_after_seconds=n):
                # Sleep + retry
                ...
```

`error.denial` is `StructuredDenial | None` carrying:
- `rule_id` — the rule or `NEVER_EXEMPTABLE` predicate that fired
- `violated_predicate` — human-readable WHY (e.g. "Destructive SQL blocked")
- `corrective` — typed `CorrectiveAction` or `None`
- `idempotency_key` — stable hash so the SDK can detect loops
- `reason_codes`, `boundary_violation`

`error.to_tool_result()` returns the gateway's pre-rendered string
ready to drop into `tool_result.content` — same text the dashboard
chip shows, no client-side template logic.

## API Reference

| Function | Description |
|----------|-------------|
| `clampd.init(dsn=None, *, name=None)` | Configure from a DSN (or `CLAMPD_DSN`) and auto-enroll. `name` sets the agent's logical name. |
| `import clampd.auto` / `clampd run -- <cmd>` | Zero-code: auto-init from `CLAMPD_DSN` + auto-wrap OpenAI/Anthropic clients. |
| `clampd.register_tool(name, category, subcategory, operation, ...)` | Declare a tool's taxonomy classification at startup. Bypasses default-deny on first use. |
| `clampd.openai(client, **opts)` | Wrap OpenAI client. `guard_stream=True` for streaming. |
| `clampd.anthropic(client, **opts)` | Wrap Anthropic client. `guard_stream=True` for streaming. |
| `clampd.guard(tool_name, **opts)` | Decorator for any function. Correctives are authored on the rule (TOML or dashboard) or Cedar policy. |
| `clampd.langchain(...)` | LangChain callback handler. |
| `clampd.adk(...)` | Google ADK `before_tool_callback`. |
| `ClampdCrewAIGuard` | CrewAI tool wrapping. |
| `clampd.delegation_headers()` / `enter_delegation(...)` | A2A delegation propagation. |
| `clampd.verify_scope_token(...)` / `require_scope(...)` | Tool-side scope-token verification (zero-trust). |
| `clampd.Category` / `Subcategory` / `Operation` | Taxonomy enums for `register_tool`. |
| `ClampdBlockedError` / `ClampdLoopError` / `ClampdUnregisteredToolError` | Typed exception hierarchy. |

## Requirements

- Python 3.10+
- A running [Clampd](https://clampd.dev) gateway

## License

BUSL-1.1
