# Clampd

Runtime security firewall for AI agents. Intercepts, inspects, and enforces policy on every tool call through a 9-stage Rust pipeline - detection, anomaly scoring, scope enforcement, delegation control, and kill switch - before anything reaches your databases, APIs, or file systems.

```python
import clampd

client = clampd.openai(OpenAI(), agent_id="my-agent")
```

```typescript
import clampd from "@clampd/sdk";

const client = clampd.openai(new OpenAI(), { agentId: "my-agent" });
```

## What it does

Your agent calls a tool. Clampd intercepts it, runs it through 75 detection rules across 5 layers, and blocks it if it looks like SQL injection, prompt injection, SSRF, path traversal, PII exfiltration, or any of the other patterns below. If it's clean, the call goes through. Response gets scanned too.

```
Agent -> SDK -> Gateway -> [Auth -> Extract -> Classify -> Policy -> Token -> Forward -> Audit]
```

## Quick Start

### 1. Run the pipeline

```bash
curl -sL https://github.com/clampd/clampd/raw/main/docker/.env.example -o .env
curl -sL https://github.com/clampd/clampd/raw/main/docker/docker-compose.proxy.yml -o docker-compose.yml

# Generate secrets
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^NATS_TOKEN=.*/NATS_TOKEN=$(openssl rand -hex 32)/" .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i "s/^AG_INTERNAL_SECRET=.*/AG_INTERNAL_SECRET=$(openssl rand -hex 64)/" .env

docker compose --profile local-infra up -d
```

### 2. Install SDK

```bash
pip install clampd          # Python
npm install @clampd/sdk     # TypeScript
```

### 3. Wrap your client

```python
import clampd
from openai import OpenAI

clampd.init(agent_id="my-agent", gateway_url="http://localhost:8080", api_key="your-key")
client = clampd.openai(OpenAI(), agent_id="my-agent")

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Look up order #1234"}],
    tools=[...],
)
```

## Detection

| Category | Examples | Layer |
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
                    +------------------------------------------+
                    |            ag-gateway (HTTP)              |
                    |  Auth -> Extract -> Classify -> Policy -> |
                    |  Token -> Forward -> Audit                |
                    +--+------+------+------+------+-----------+
                       |      |      |      |      |
                 ag-intent  ag-policy  ag-token  ag-kill
                       |
                  ag-engine (5 detection layers)
                  L0: Binary funnel (yara, entropy, magic bytes)
                  L1: Rule engine (75 rules, TOML + SIGMA)
                  L2: Dictionary (Aho-Corasick, O(n) scan)
                  L3: Signals (40+ compound micro-signals)
                  L4: Normalizer (13-step recursive decode)
                       |
                    ag-risk --> ag-shadow --> ClickHouse
```

Everything runs in your infrastructure. Audit logs go to your ClickHouse instance.

## Source Code

| Directory | Contents | License |
|---|---|---|
| [`sdk/`](sdk/) | Python + TypeScript SDKs | Apache 2.0 |
| [`proto/`](proto/) | gRPC API contracts | Apache 2.0 |
| [`docker/`](docker/) | Compose files, .env.example | Apache 2.0 |
| [`services/crates/ag-gateway/`](services/crates/ag-gateway/) | HTTP gateway, 9-stage pipeline | BSL 1.1 |
| [`services/crates/ag-engine/`](services/crates/ag-engine/) | Detection engine (parse, compile, execute, signals) | BSL 1.1 |
| [`services/crates/ag-shadow/`](services/crates/ag-shadow/) | Audit pipeline, PII masking | BSL 1.1 |
| [`services/crates/ag-common/`](services/crates/ag-common/) | Shared types | BSL 1.1 |
| [`bin/`](bin/) | CLI binary | BSL 1.1 |

The full rule library (75 TOML patterns), keyword dictionary, and compliance mappings are compiled into the Docker images.

## CLI

```bash
curl -sL https://github.com/clampd/clampd/raw/main/bin/clampd-v0.8.0-linux-amd64 -o clampd
chmod +x clampd

./clampd agent list
./clampd policy evaluate --agent my-agent --tool database.query --params '{"sql":"SELECT 1"}'
./clampd risk review --agent my-agent
./clampd rules import --format sigma my-rules/
./clampd keywords add --keyword "exfiltrate" --category data_exfil --weight 0.9
```

## MCP Proxy

Wrap any MCP server with security scanning:

```bash
docker compose -f docker-compose.proxy.yml -f docker-compose.demo.yml --profile mcp up -d
```

```bash
docker run -e UPSTREAM_MCP="npx -y @modelcontextprotocol/server-filesystem /tmp" \
           -e AG_GATEWAY_URL=http://localhost:8080 \
           -e AG_API_KEY=your-key \
           -e AG_AGENT_ID=your-agent-id \
           -p 3003:3003 \
           ghcr.io/clampd/clampd/mcp-proxy:v0.8.0
```

## Examples

- [Python: Guard any function](sdk/python/examples/01_guard.py)
- [TypeScript: OpenAI wrapper](sdk/typescript/examples/02-openai.ts)
- [TypeScript: Anthropic wrapper](sdk/typescript/examples/03-anthropic.ts)
- [TypeScript: Vercel AI](sdk/typescript/examples/05-vercel-ai.ts)
- [TypeScript: Schema injection detection](sdk/typescript/examples/06-schema-injection.ts)
- [Multi-agent A2A workflow](sdk/typescript/examples/07-a2a-workflow.ts)

## Compliance

- **HIPAA** - 18 Safe Harbor PHI identifiers, 27 PII regex patterns, ClickHouse audit trail
- **GDPR** - PII masking via regex + NER in ag-shadow, 4-level data classification (Restricted/Confidential/Internal/Public)
- **SOC 2** - Session fingerprinting with sliding TTL, 7 anomaly detectors, 8-layer kill cascade
- **ISO 27001** - Access control, audit logging, encryption in transit

Detection features (Luhn credit card validation, secrets scanning, multi-layer defense) support PCI-DSS and NIST alignment but don't have dedicated compliance report generators yet.

## License

- **SDKs + Proto + Docker** - [Apache 2.0](LICENSES/Apache-2.0.txt)
- **Services** - [BSL 1.1](LICENSES/BUSL-1.1.txt) (converts to Apache 2.0 in 2029)
- **Rule content** - [Proprietary](LICENSES/LicenseRef-Proprietary.txt)

## Links

- https://clampd.dev
- PyPI: `pip install clampd`
- npm: `npm install @clampd/sdk`
- Docker: `ghcr.io/clampd/clampd/ag-gateway:v0.8.0`
