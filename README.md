# Clampd — Runtime Security for AI Agents

Clampd is a security proxy that sits between AI agents and their tools. Every tool call passes through a 9-stage pipeline — authenticate, identify, extract, session, classify, evaluate, token exchange, forward, audit — in under 15ms.

Built in Rust. 9 microservices. 36 built-in detection rules. Works with OpenAI, Anthropic, LangChain, Google ADK, MCP, and any custom framework.

## Why

AI agents call tools with full credentials. One prompt injection turns your helpful assistant into an attacker with insider access. Clampd stops that by:

- Intercepting every tool call before execution
- Scoring risk with regex rules + optional ML model escalation
- Blocking destructive SQL, SSRF, credential theft, path traversal, prompt injection
- Minting short-lived micro-tokens (Ed25519, 30s TTL) instead of passing raw credentials
- Logging everything to ClickHouse for audit

## Quick Start

### 1. Start infrastructure

```bash
cd clampd/
docker compose up -d postgres redis nats clickhouse
```

### 2. Start Rust services

```bash
# Option A: Docker (recommended)
docker compose up -d ag-registry ag-intent ag-policy ag-token ag-gateway ag-shadow ag-kill ag-risk ag-control

# Option B: Build from source
cd services/
cargo build --release --workspace
# Start each binary (see Service Configuration below)
```

### 3. Start dashboard (optional)

```bash
docker compose --profile dashboard up -d
# Web UI: http://localhost:3000
# API: http://localhost:3001
```

### 4. Install SDK

```bash
pip install clampd          # Python
npm install @clampd/sdk     # TypeScript
```

### 5. Guard your agent (1 line)

**Python:**
```python
import clampd
from openai import OpenAI

client = clampd.openai(OpenAI(), agent_id="my-agent")
# All tool calls now go through the 9-stage pipeline
```

**TypeScript:**
```typescript
import clampd from "@clampd/sdk";

const wrapped = clampd.openai(client, { agentId: "my-agent" });
// All tool calls intercepted and verified
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ag-gateway (HTTP)                         │
│  Stage 1: Auth → 2: Identify → 3: Extract → 4: Session          │
│  → 5: Classify → 5.5: Model Escalation → 6: Policy              │
│  → 7: Token Exchange → 8: Forward → 9: Audit                    │
└───────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬────────┘
        │      │      │      │      │      │      │      │
   ag-registry │ ag-intent   │ ag-policy   │ ag-token    │
     (gRPC)    │  (gRPC)     │  (gRPC)     │  (gRPC)     │
               │             │             │             │
          ag-shadow     ag-risk        ag-kill      ag-control
          (NATS→CH)    (NATS+WS)    (gRPC+Redis)    (gRPC)

Supporting: PostgreSQL · Redis · NATS JetStream · ClickHouse
```

### Services

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| ag-gateway | 8080 | HTTP/REST | API gateway, 9-stage pipeline |
| ag-registry | 50051 | gRPC | Agent registration, credentials, Redis cache |
| ag-intent | 50052 | gRPC | Intent classification, 36 rules, encoding detection |
| ag-policy | 50053 | gRPC | Policy evaluation, OPA sidecar integration |
| ag-token | 50054 | gRPC | Micro-token minting (Ed25519), IDP integration |
| ag-kill | 50055 | gRPC | Emergency kill switch, 8-layer cascade |
| ag-risk | 50056 | gRPC+WS | EMA risk scoring, anomaly detection, WebSocket feed |
| ag-shadow | 50057 | NATS consumer | Event logging to ClickHouse, PII tokenization |
| ag-control | 50058 | gRPC | License management, feature gating |

### Supporting Services

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL 16 | 5432 | Agent registry, policies, licenses, dashboard |
| Redis 7 | 6379 | Session state, deny lists, circuit breakers, caching |
| NATS 2 | 4222 | Event streaming (JetStream), policy distribution |
| ClickHouse 24 | 8123 | Audit trail, shadow event storage |

---

## SDK Reference

### Python

```python
import clampd

# Global init (optional — or pass agent_id to each call)
clampd.init(agent_id="my-agent", gateway_url="http://localhost:8080")

# Guard OpenAI
client = clampd.openai(OpenAI(), agent_id="my-agent")

# Guard Anthropic/Claude
client = clampd.anthropic(Anthropic(), agent_id="my-agent")

# Guard any function
@clampd.guard("database.query", agent_id="my-agent")
def run_query(sql: str) -> str:
    return db.execute(sql)

# LangChain (guards ALL tools via callback)
agent.invoke(input, config={"callbacks": [clampd.langchain(agent_id="my-agent")]})

# Google ADK
agent = Agent(
    tools=[search],
    before_tool_callback=clampd.adk(agent_id="my-agent"),
)

# MCP proxy
# python -m clampd.mcp_server --downstream "npx server-filesystem /tmp" --agent-id "my-agent"
```

### TypeScript

```typescript
import clampd from "@clampd/sdk";

// Global init (optional)
clampd.init({ agentId: "my-agent", gatewayUrl: "http://localhost:8080" });

// Guard OpenAI
const wrapped = clampd.openai(client, { agentId: "my-agent" });

// Guard Anthropic/Claude
const wrapped = clampd.anthropic(client, { agentId: "my-agent" });

// Guard any async function
const guarded = clampd.guard(myFn, { agentId: "my-agent", toolName: "db.query" });

// Wrap OpenAI tool definitions
const safeTools = clampd.tools(myTools, { agentId: "my-agent" });
```

### Response Inspection (opt-in)

```python
# Check tool responses for PII, data anomalies, poisoned data
client = clampd.openai(OpenAI(), agent_id="my-agent", check_response=True)

@clampd.guard("database.query", check_response=True)
def run_query(sql: str) -> str:
    return db.execute(sql)

# Google ADK: returns (before_cb, after_cb) tuple
before_cb, after_cb = clampd.adk(agent_id="my-agent", check_response=True)
```

```typescript
const guarded = clampd.guard(myFn, {
  agentId: "my-agent",
  toolName: "db.query",
  checkResponse: true,
});
```

### SDK Options

| Option | Python | TypeScript | Default |
|--------|--------|-----------|---------|
| Agent ID | `agent_id="..."` | `agentId: "..."` | Required |
| Gateway URL | `gateway_url="..."` | `gatewayUrl: "..."` | `http://localhost:8080` |
| API key | `api_key="..."` | `apiKey: "..."` | `clmpd_demo_key` |
| Fail open | `fail_open=True` | `failOpen: true` | `False` |
| Response check | `check_response=True` | `checkResponse: true` | `False` |
| JWT secret | `secret="..."` | via env `JWT_SECRET` | — |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAMPD_AGENT_ID` | Default agent ID | — |
| `CLAMPD_GATEWAY_URL` | Gateway URL | `http://localhost:8080` |
| `CLAMPD_API_KEY` | API key | `clmpd_demo_key` |
| `JWT_SECRET` | HMAC-SHA256 secret for JWT signing | — |

---

## Service Configuration

All services read configuration from environment variables.

### ag-gateway

| Variable | Default | Description |
|----------|---------|-------------|
| `AG_GATEWAY_PORT` | `8080` | HTTP listen port |
| `AG_GATEWAY_METRICS_PORT` | `9090` | Prometheus metrics port |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection |
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS connection |
| `REGISTRY_URL` | `http://127.0.0.1:50051` | ag-registry gRPC |
| `INTENT_URL` | `http://127.0.0.1:50052` | ag-intent gRPC |
| `POLICY_URL` | `http://127.0.0.1:50053` | ag-policy gRPC |
| `TOKEN_URL` | `http://127.0.0.1:50054` | ag-token gRPC |
| `JWT_SECRET` | `dev-secret-change-me` | JWT validation secret |

### ag-registry

| Variable | Default | Description |
|----------|---------|-------------|
| `AG_REGISTRY_PORT` | `50051` | gRPC listen port |
| `DATABASE_URL` | `postgres://clampd:clampd_dev@127.0.0.1:5432/clampd` | PostgreSQL |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Redis cache |
| `NATS_URL` | `nats://127.0.0.1:4222` | NATS |

### ag-risk

| Variable | Default | Description |
|----------|---------|-------------|
| `AG_RISK_PORT` | `50056` | gRPC listen port |
| `AG_RISK_WS_PORT` | `8081` | WebSocket feed port |
| `EMA_ALPHA` | `0.3` | EMA smoothing factor |
| `AUTO_SUSPEND_THRESHOLD` | `0.9` | Auto-suspend at this score |

### Model Escalation (hybrid rules + ML)

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_ESCALATION_ENABLED` | `false` | Enable gray-zone model escalation |
| `MODEL_ESCALATION_LOW` | `0.2` | Below = instant allow |
| `MODEL_ESCALATION_HIGH` | `0.75` | Above = instant block |
| `MODEL_ESCALATION_BACKEND` | `http` | `http` or `onnx` |
| `MODEL_URL` | — | Remote classification endpoint |
| `MODEL_TIMEOUT_MS` | `200` | Model call timeout |
| `MODEL_FAIL_OPEN` | `true` | Use rules score if model fails |
| `MODEL_CHECK_UNMATCHED` | `false` | Also escalate when no rules match |

---

## Docker

### Images

All production images use multi-stage builds with `gcr.io/distroless/cc-debian12:nonroot` as the runtime base. No shell, no package manager, non-root user.

```bash
# Build a service image
docker build -f services/deploy/Dockerfile.service \
  --build-arg SERVICE_NAME=ag-gateway \
  -t clampd/ag-gateway:latest .

# Build the CLI
docker build -f services/deploy/Dockerfile.cli \
  -t clampd/clampd-cli:latest .

# Extract CLI binary from Docker
docker create --name cli-extract clampd/clampd-cli:latest
docker cp cli-extract:/app ./clampd
docker rm cli-extract
```

### Docker Compose

**Full stack** (services + infrastructure):
```bash
cd clampd/
docker compose up -d                          # Infrastructure only
docker compose --profile full up -d           # Everything
docker compose --profile dashboard up -d      # + Dashboard
```

**Dashboard only** (if services run elsewhere):
```bash
cd dashboard/
cp .env.example .env   # Edit with your config
docker compose up -d
```

### Hardening Checklist

- [x] Multi-stage builds (build → distroless runtime)
- [x] Non-root user (`nonroot:nonroot` in distroless)
- [x] No shell in runtime image (distroless)
- [x] `cap_drop: ALL` in docker-compose
- [x] `security_opt: no-new-privileges:true`
- [x] `read_only: true` filesystem with tmpfs for /tmp
- [x] Alpine base images for infrastructure (PostgreSQL, Redis, NATS, ClickHouse)
- [x] Health checks on all services
- [x] No secrets in image layers (passed via env vars)
- [ ] Image scanning with Trivy/Snyk (recommended)
- [ ] Signed images with cosign (recommended)

### Image Sizes

| Image | Base | Approx. Size |
|-------|------|-------------|
| ag-gateway | distroless | ~25MB |
| ag-registry | distroless | ~25MB |
| ag-intent | distroless | ~22MB |
| ag-* (others) | distroless | ~20-25MB |
| dashboard-api | node:22-alpine | ~180MB |
| dashboard-web | node:22-alpine | ~250MB |
| clampd-cli | distroless | ~25MB |

---

## Dashboard

**Stack:** Next.js 16 (React 19) + Fastify 5 + Drizzle ORM + PostgreSQL

### Features
- Kill, suspend, or pause agents in real-time
- Policy editor with Monaco (syntax highlighting, validation)
- Custom rules DSL with hot-reload
- Live risk feed via WebSocket
- Agent registry with scoped credentials
- Team management with RBAC
- Stripe billing integration

### Setup

```bash
cd dashboard/
cp .env.example .env
# Edit .env with your JWT_SECRET, DATABASE_URL, etc.

# Start infrastructure
docker compose up -d

# Start API (port 3001)
cd api && npm install && npm run dev

# Start Web (port 3000)
cd ../web && npm install && npm run dev
```

### Key Environment Variables

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | Auth token signing key |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection |
| `NATS_URL` | NATS connection |
| `GATEWAY_URL` | ag-gateway URL (for proxying) |
| `RESEND_API_KEY` | Email delivery (optional) |
| `STRIPE_SECRET_KEY` | Billing (optional) |
| `GOOGLE_CLIENT_ID` | OAuth (optional) |

---

## CLI (clampd)

```bash
# Install
pip install clampd   # or extract from Docker image

# Configure
clampd config init   # Creates ~/.clampd/config.toml

# Commands
clampd cluster status                    # Health check all 9 services
clampd agent list                        # List agents with state & risk
clampd agent inspect <id>                # Full agent detail
clampd kill <agent-id> --reason "..."    # Emergency kill switch
clampd policy list                       # Active policies
clampd policy import <file>              # Import from OPA, YAML, or Invariant
clampd risk feed                         # Stream real-time risk scores
clampd audit query --tool database.*     # Query ClickHouse audit trail
clampd watch                             # Live TUI dashboard
clampd demo --scenario breach            # Run demo with real pipeline
clampd token list                        # Active micro-tokens
clampd apikey list                       # API keys with scopes
clampd webhook list                      # Webhook delivery status
clampd license show                      # License tier & limits
```

---

## Security

### Production Checklist

- [ ] Set `JWT_SECRET` to a strong random value (32+ chars)
- [ ] Change default PostgreSQL password
- [ ] Enable TLS on all service ports
- [ ] Restrict Redis access (bind, requirepass)
- [ ] Set `MODEL_FAIL_OPEN=false` for strict mode
- [ ] Review and customize the 36 built-in rules
- [ ] Configure rate limiting per agent
- [ ] Set up webhook alerts for high-risk events
- [ ] Enable PII masking in ag-shadow (`PII_MASKING=true`)
- [ ] Rotate Ed25519 token signing keys regularly
- [ ] Configure OIDC SSO for dashboard access

### Threat Model

| Threat | Detection Rule(s) | Score |
|--------|-------------------|-------|
| Destructive SQL (DROP, TRUNCATE) | R001 | 0.95 |
| Credential file access (.env, .ssh) | R002 | 0.98 |
| SSRF (169.254.x, localhost) | R004 | 0.92 |
| SQL injection (UNION SELECT, OR 1=1) | R005 | 0.92 |
| Path traversal (../../etc/passwd) | R006 | 0.85 |
| Command injection (;rm, |cat) | R007 | 0.92 |
| Prompt injection patterns | R009 | 0.88 |
| Reverse shell (nc -e, bash -i) | R010 | 0.97 |
| PII exfiltration (SSN, credit card) | R011, R013 | 0.80-0.90 |
| XSS payloads | R015 | 0.75 |
| Mass data access (LIMIT >10000) | R025 | 0.70 |

---

## Development

```bash
# Build all Rust services
cd clampd/
make build

# Run tests
make test              # All Rust tests
make test-ag-intent    # Single crate

# Python SDK tests
cd sdk/python/
pip install -e ".[dev]"
pytest tests/ -v

# TypeScript SDK tests
cd sdk/typescript/
npm install
npx vitest run

# Format & lint
make fmt-fix
make clippy
```

---

## License

License TBD. Source-available release coming soon.

---

Built by [Clampd](https://clampd.dev). Shipped for teams running AI agents in production.
