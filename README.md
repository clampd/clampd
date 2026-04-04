# Clampd - Runtime Security for AI Agents

Guard every AI agent tool call with a 9-stage security pipeline. One line to integrate. Zero prompts leave your infrastructure unscanned.

```python
import clampd

client = clampd.openai(OpenAI(), agent_id="my-agent")
# Every tool call is now guarded - SQL injection, prompt injection,
# PII leaks, SSRF, path traversal, and 70+ more patterns detected.
```

```typescript
import clampd from "@clampd/sdk";

const client = clampd.openai(new OpenAI(), { agentId: "my-agent" });
```

## Why Clampd?

AI agents call tools - databases, APIs, file systems, shells. One prompt injection and your agent runs `DROP TABLE users` or exfiltrates credentials to `webhook.site`.

Clampd sits between your agent and its tools. Every call passes through a 9-stage pipeline:

```
Agent → SDK → Gateway → [Auth → Extract → Classify → Policy → Token → Forward → Audit]
                              ↓         ↓          ↓        ↓
                          75 rules   5-layer     OPA +    Scope
                          4 layers   engine      Cedar    tokens
```

## Quick Start

### 1. Start the security pipeline

```bash
# Download compose + config
curl -sL https://github.com/clampd/clampd/raw/main/docker/.env.example -o .env
curl -sL https://github.com/clampd/clampd/raw/main/docker/docker-compose.proxy.yml -o docker-compose.yml

# Set your secrets
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^NATS_TOKEN=.*/NATS_TOKEN=$(openssl rand -hex 32)/" .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i "s/^AG_INTERNAL_SECRET=.*/AG_INTERNAL_SECRET=$(openssl rand -hex 64)/" .env

# Start (with local Postgres/Redis/ClickHouse)
docker compose --profile local-infra up -d
```

### 2. Install the SDK

```bash
pip install clampd          # Python
npm install @clampd/sdk     # TypeScript
```

### 3. Guard your agent

```python
import clampd
from openai import OpenAI

clampd.init(agent_id="my-agent", gateway_url="http://localhost:8080", api_key="your-key")
client = clampd.openai(OpenAI(), agent_id="my-agent")

# This is now guarded - malicious tool calls are blocked
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Look up order #1234"}],
    tools=[...],
)
```

## What Gets Detected

| Category | Examples | Detection Layer |
|---|---|---|
| SQL Injection | `UNION SELECT`, `; DROP TABLE`, `CHAR()` obfuscation | L1 Rules + L3 Signals |
| Prompt Injection | "ignore your instructions", goal hijacking, 20 languages | L2 Dictionary + L1 Rules |
| Path Traversal | `../../etc/passwd`, null byte bypass, double-ext bypass | L1 Rules + L3 Signals |
| SSRF | Cloud metadata `169.254.169.254`, DNS rebinding, internal IPs | L3 Signals + L1 Rules |
| Command Injection | Pipe chains, semicolon exec, env var expansion | L1 Rules + L3 Signals |
| PII/PHI Leaks | SSN, credit cards (Luhn-validated), medical records | L1 Rules + Response Scan |
| Data Exfiltration | Webhook.site, base64 blobs, data URIs | L3 Signals |
| Encoding Evasion | Unicode homoglyphs, double encoding, zero-width chars | L0 Funnel + L3 Signals |
| Privilege Escalation | Admin keywords, token patterns, scope violations | L3 Signals + Policy |
| Agent-to-Agent Abuse | Delegation chain manipulation, rug-pull detection | Delegation + A2A |

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │            ag-gateway (HTTP)            │
                    │  9 stages: Auth → Extract → Classify →  │
                    │  Policy → Token → Forward → Audit       │
                    └──┬──────┬──────┬──────┬──────┬─────────┘
                       │      │      │      │      │
                 ag-intent  ag-policy  ag-token  ag-kill
                 (classify)  (decide)  (scope)  (emergency)
                       │
                  ag-engine (5-layer detection)
                  ├─ L0: Binary funnel (yara, entropy, magic bytes)
                  ├─ L1: Rule engine (75 rules, TOML + SIGMA)
                  ├─ L2: Dictionary (Aho-Corasick, 1000+ keywords)
                  ├─ L3: Signals (40+ compound micro-signals)
                  └─ L4: Normalizer (13-step recursive decode)
                       │
                    ag-risk ──→ ag-shadow ──→ YOUR ClickHouse
                   (scoring)    (PII mask)    (audit logs)
```

**All services run in YOUR infrastructure.** Audit logs go to YOUR ClickHouse. No data leaves your network.

## Read the Source

This repository contains the source code for Clampd's security pipeline. We open it so you can verify:

**"Every byte of your LLM traffic flows through code you can read here."**

| Directory | What's there | License |
|---|---|---|
| [`sdk/`](sdk/) | Python + TypeScript SDKs (full source) | Apache 2.0 |
| [`proto/`](proto/) | gRPC API contracts | Apache 2.0 |
| [`docker/`](docker/) | Compose files + .env.example | Apache 2.0 |
| [`services/crates/ag-gateway/`](services/crates/ag-gateway/) | HTTP gateway - 9-stage pipeline | BSL 1.1 |
| [`services/crates/ag-engine/`](services/crates/ag-engine/) | Detection engine (parse, compile, execute, signals) | BSL 1.1 |
| [`services/crates/ag-shadow/`](services/crates/ag-shadow/) | Audit pipeline + PII masking | BSL 1.1 |
| [`services/crates/ag-common/`](services/crates/ag-common/) | Shared types | BSL 1.1 |
| [`bin/`](bin/) | Pre-built CLI binary | BSL 1.1 |

**What's NOT in this repo:** The full rule library (75 TOML patterns), full keyword dictionary (1000+ entries), compliance mappings, dashboard, and deployment configs. These ship in the official Docker images.

## CLI

```bash
# Download
curl -sL https://github.com/clampd/clampd/raw/main/bin/clampd-v0.8.0-linux-amd64 -o clampd
chmod +x clampd

# Use
./clampd agent list
./clampd policy evaluate --agent my-agent --tool database.query --params '{"sql":"SELECT 1"}'
./clampd risk review --agent my-agent
./clampd rules import --format sigma my-rules/
./clampd keywords add --keyword "exfiltrate" --category data_exfil --weight 0.9
```

## MCP Proxy

Wrap any MCP server with Clampd security - zero code changes:

```bash
docker compose -f docker-compose.proxy.yml -f docker-compose.demo.yml --profile mcp up -d
```

Or run standalone:

```bash
docker run -e UPSTREAM_MCP="npx -y @modelcontextprotocol/server-filesystem /tmp" \
           -e AG_GATEWAY_URL=http://localhost:8080 \
           -e AG_API_KEY=your-key \
           -e AG_AGENT_ID=your-agent-id \
           -p 3003:3003 \
           ghcr.io/clampd/clampd/mcp-proxy:v0.8.0
```

## SDK Examples

- [Python: Guard any function](sdk/python/examples/01_guard.py)
- [TypeScript: OpenAI wrapper](sdk/typescript/examples/02-openai.ts)
- [TypeScript: Anthropic wrapper](sdk/typescript/examples/03-anthropic.ts)
- [TypeScript: Vercel AI](sdk/typescript/examples/05-vercel-ai.ts)
- [TypeScript: Schema injection detection](sdk/typescript/examples/06-schema-injection.ts)
- [Multi-agent A2A workflow](sdk/typescript/examples/07-a2a-workflow.ts)

## Compliance

Clampd maps detection rules to regulatory frameworks:

- **HIPAA** - PHI detection (18 Safe Harbor identifiers), audit trail via ClickHouse
- **PCI-DSS** - Credit card detection (Luhn-validated), secrets scanning (6 pattern types)
- **GDPR** - PII masking in audit logs (regex + NER), 4-level data classification
- **SOC 2** - Session monitoring with fingerprinting, 7-type anomaly detection, 8-layer kill switch
- **EU AI Act** - Anomaly reasoning descriptions, risk scoring (component-level transparency in progress)
- **NIST AI RMF** - 5-layer policy engine + 9-stage pipeline, real-time monitoring via WebSocket + NATS

## License

- **SDKs + Proto + Docker** - [Apache 2.0](LICENSES/Apache-2.0.txt)
- **Services (Rust)** - [BSL 1.1](LICENSES/BUSL-1.1.txt) (converts to Apache 2.0 in 2029)
- **Rule content (stubs only)** - [Proprietary](LICENSES/LicenseRef-Proprietary.txt)

The BSL means: read it, audit it, self-host it - but don't offer a competing managed guardrail service.

## Links

- Website: https://clampd.dev
- Docs: https://docs.clampd.dev
- SDK (PyPI): `pip install clampd`
- SDK (npm): `npm install @clampd/sdk`
- Docker: `ghcr.io/clampd/clampd/ag-gateway:v0.8.0`
