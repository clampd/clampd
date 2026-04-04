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

```python
import clampd
from openai import OpenAI

# Configure once at startup
clampd.init(
    agent_id="my-agent",
    secret="ags_...",              # from dashboard → Agent → Secret
    gateway_url="http://localhost:8080",
    api_key="ag_live_...",
)

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

## What's New in 0.5.0

- **Per-agent JWT identity** — each agent authenticates independently in multi-agent systems
- **Streaming guard** — opt-in tool call interception for streaming responses (`guard_stream=True`)
- **Circuit breaker & retry** — automatic retry with exponential backoff
- **CrewAI integration** — guard CrewAI agent tool calls
- **216 detection rules** with Aho-Corasick prefilter (22μs at 10K rules)

## Configuration

```python
# Option 1: Single agent (simple)
clampd.init(
    agent_id="my-agent",
    secret="ags_...",
    gateway_url="http://localhost:8080",
    api_key="ag_live_...",
)

# Option 2: Multi-agent (per-agent identity)
clampd.init(
    agent_id="orchestrator",
    api_key="ag_live_...",
    agents={
        "orchestrator": os.environ["CLAMPD_SECRET_orchestrator"],
        "research-agent": os.environ["CLAMPD_SECRET_research_agent"],
        "writer-agent": os.environ["CLAMPD_SECRET_writer_agent"],
    },
)

# Option 3: Environment variables
# CLAMPD_GATEWAY_URL=http://localhost:8080
# CLAMPD_API_KEY=ag_live_...
# CLAMPD_SECRET_orchestrator=ags_...
# CLAMPD_SECRET_research_agent=ags_...
```

## Anthropic / Claude

```python
import clampd
from anthropic import Anthropic

clampd.init(agent_id="my-agent", secret="ags_...")
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

handler = clampd.langchain(agent_id="my-agent", secret="ags_...")

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
    before_tool_callback=clampd.adk(agent_id="my-agent", secret="ags_..."),
)
```

## Multi-Agent (A2A Delegation)

```python
import os
import clampd

# Each agent authenticates with its own secret.
# Delegation chains are tracked automatically.
clampd.init(
    agent_id="orchestrator",
    api_key="ag_live_...",
    agents={
        "orchestrator": os.environ["CLAMPD_SECRET_orchestrator"],
        "research-agent": os.environ["CLAMPD_SECRET_research_agent"],
    },
)

# research-agent gets its own JWT (sub=research-agent).
# Kill "research-agent" from dashboard → only this agent is blocked.
@clampd.guard("web.search", agent_id="research-agent")
def search(query: str):
    return web_search(query)
```

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

clampd.init(agent_id="crew-agent", secret="ags_...")
guard = ClampdCrewAIGuard()

# Wrap CrewAI tools
safe_tool = guard.wrap_tool(my_tool)
```

## Direct Guard (any function)

```python
import clampd

clampd.init(agent_id="my-agent", secret="ags_...")

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

```python
from clampd import ClampdBlockedError

try:
    run_query("DROP TABLE users")
except ClampdBlockedError as e:
    print(f"Blocked: {e}")
    # e.risk_score, e.denial_reason, e.request_id
```

## API Reference

| Function | Description |
|----------|-------------|
| `clampd.init(...)` | Configure global client. `agents` for per-agent secrets. |
| `clampd.openai(client, **opts)` | Wrap OpenAI client. `guard_stream=True` for streaming. |
| `clampd.anthropic(client, **opts)` | Wrap Anthropic client. `guard_stream=True` for streaming. |
| `clampd.guard(tool_name, **opts)` | Decorator for any function. `agent_id` for per-agent identity. |
| `clampd.langchain(...)` | LangChain callback handler |
| `clampd.adk(...)` | Google ADK before_tool_callback |
| `ClampdCrewAIGuard` | CrewAI tool wrapping |

## Requirements

- Python 3.10+
- A running [Clampd](https://clampd.dev) gateway

## License

BUSL-1.1
