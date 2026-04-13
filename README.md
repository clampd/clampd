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

Your agent calls a tool. Clampd intercepts it, runs it through 150+ detection rules across 5 layers, and blocks it if it looks like SQL injection, prompt injection, SSRF, path traversal, PII exfiltration, or any of the other patterns below. If it's clean, the call goes through. Response gets scanned too.

```
Agent -> SDK -> Gateway -> [Auth -> Extract -> Classify -> Policy -> Token -> Forward -> Audit]
```

## Quick Start

### 1. Run the proxy (security pipeline)

```bash
curl -sL https://github.com/clampd/clampd/raw/main/docker/docker-compose.proxy.yml -o docker-compose.yml
curl -sL https://github.com/clampd/clampd/raw/main/docker/setup.sh | sh

# Add your license key (get one at https://app.clampd.dev)
# Then edit .env and set CLAMPD_LICENSE_KEY

docker compose --profile local-infra up -d
```

### 2. Run the dashboard (optional)

```bash
curl -sL https://github.com/clampd/clampd/raw/main/docker/docker-compose.control.yml -o docker-compose.control.yml
docker compose -f docker-compose.control.yml --profile local-infra up -d
```

<details>
<summary>Manual setup (without setup.sh)</summary>

```bash
curl -sL https://github.com/clampd/clampd/raw/main/docker/.env.example -o .env

sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^NATS_TOKEN=.*/NATS_TOKEN=$(openssl rand -hex 32)/" .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$(openssl rand -hex 16)/" .env
sed -i "s/^AG_INTERNAL_SECRET=.*/AG_INTERNAL_SECRET=$(openssl rand -hex 64)/" .env

docker compose --profile local-infra up -d
```

</details>

### 3. Install SDK

```bash
pip install clampd          # Python
npm install @clampd/sdk     # TypeScript
```

### 4. Wrap your client

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
                  L1: Rule engine (152 rules, TOML + SIGMA)
                  L2: Dictionary (Aho-Corasick, O(n) scan)
                  L3: Signals (40+ compound micro-signals)
                  L4: Normalizer (13-step recursive decode)
                       |
                    ag-risk --> ag-shadow --> ClickHouse
```

Everything runs in your infrastructure. Audit logs go to your ClickHouse instance.

## What's in This Repo

**Open source:**

| Directory | Contents | License |
|---|---|---|
| [`sdk/`](sdk/) | Python + TypeScript SDKs | Apache 2.0 |
| [`src/clampd-guard/`](src/clampd-guard/) | Claude Code & Cursor guard — full source + tests | BSL 1.1 |
| [`src/ag-gateway/`](src/ag-gateway/) | HTTP gateway, 9-stage request pipeline | BSL 1.1 |
| [`src/ag-shadow/`](src/ag-shadow/) | Audit pipeline, PII masking | BSL 1.1 |
| [`proto/`](proto/) | gRPC API contracts | Apache 2.0 |
| [`docker/`](docker/) | Compose files, setup script, .env.example | Apache 2.0 |
| [`bin/`](bin/) | Pre-built CLI binaries | BSL 1.1 |

**Docker images only** (closed source — this is the detection engine you're paying for):

| Image | What it does |
|---|---|
| `ghcr.io/clampd/ag-engine` | 152 rules, 5 detection layers, keyword dictionary |
| `ghcr.io/clampd/ag-intent` | Classification, session patterns, encoding detection |
| `ghcr.io/clampd/ag-policy` | Policy engine, scope exemptions, Cedar policies |
| `ghcr.io/clampd/ag-risk` | EMA scoring, anomaly detectors, behavioral baselines |
| `ghcr.io/clampd/ag-kill` | Kill cascade, auto-suspend, permanent kill |
| `ghcr.io/clampd/ag-registry` | Agent lifecycle, tool registration |
| `ghcr.io/clampd/ag-token` | Token exchange, scope tokens |
| `ghcr.io/clampd/ag-control` | SaaS bridge, API key sync, delegation sync |

## CLI

```bash
# Install (Linux/macOS)
curl -fsSL https://clampd.dev/install.sh | sh

# Or download directly
curl -sL https://github.com/clampd/clampd/releases/latest/download/clampd-linux-amd64.tar.gz | tar xz
sudo mv clampd /usr/local/bin/

# Usage
clampd license activate --license "$CLAMPD_LICENSE_KEY"
clampd agent list
clampd policy evaluate --agent my-agent --tool database.query --params '{"sql":"SELECT 1"}'
clampd risk review --agent my-agent
clampd rules import --format sigma my-rules/
clampd keywords add --keyword "exfiltrate" --category data_exfil --weight 0.9
```

Binaries available for Linux (amd64/arm64), macOS (arm64), and Windows (amd64).

## Claude Code & Cursor Protection

`clampd-guard` is a standalone binary that hooks into Claude Code and Cursor as a PreToolUse/PostToolUse guard. Every tool call is verified against your Clampd gateway before execution.

```bash
# Install
curl -fsSL https://clampd.dev/install-guard.sh | sh

# Setup (one time — installs hooks automatically)
clampd-guard setup \
  --url https://your-gateway:8080 \
  --key your-api-key \
  --agent your-agent-id \
  --secret your-agent-secret

# Sync tools for dashboard visibility
clampd-guard sync
```

What it does:
- **PreToolUse**: Blocks Bash commands, file writes, web fetches before they execute
- **PostToolUse**: Scans tool output for PII, secrets, sensitive data
- **MCP tool discovery**: Finds all MCP servers in Claude Code and Cursor configs
- **Managed config**: Security teams can push `/etc/clampd/guard.json` via MDM

3.2MB binary, <100ms per check. Config at `~/.clampd/guard.json`.

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
           ghcr.io/clampd/mcp-proxy:v0.9.0
```

## Examples

**Python SDK:**
- [Guard any function](sdk/python/examples/01_guard.py)
- [A2A multi-agent workflow](sdk/python/examples/07_a2a_workflow.py)
- [GitHub Models integration](sdk/python/examples/08_github_models.py)

**TypeScript SDK:**
- [Guard a function](sdk/typescript/examples/01-guard.ts)
- [OpenAI wrapper](sdk/typescript/examples/02-openai.ts)
- [Anthropic wrapper](sdk/typescript/examples/03-anthropic.ts)
- [Google ADK](sdk/typescript/examples/04-adk.ts)
- [Vercel AI](sdk/typescript/examples/05-vercel-ai.ts)
- [Schema injection detection](sdk/typescript/examples/06-schema-injection.ts)
- [A2A multi-agent workflow](sdk/typescript/examples/07-a2a-workflow.ts)
- [GitHub Models](sdk/typescript/examples/08-github-models.ts)

**Advanced:**
- [A2A attack simulations](examples/a2a_attacks.py)
- [LangGraph A2A](examples/langgraph_a2a.py)
- [SIGMA rule import](examples/sigma-rules/)

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
- Docker: `ghcr.io/clampd/ag-gateway:v0.9.0`
