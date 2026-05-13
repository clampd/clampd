#!/bin/bash
# Create a GitHub Release on clampd/clampd with all public artifacts.
#
# Prerequisites:
#   1. gh auth login (GitHub CLI authenticated)
#   2. public-repo pushed to clampd/clampd
#   3. sync-to-public.sh already ran (binaries in bin/)
#
# Usage:
#   ./create-release.sh           # uses VERSION file
#   ./create-release.sh v0.9.1    # override version

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${1:-v$(cat "$SCRIPT_DIR/VERSION" | tr -d '[:space:]')}"
RELEASE_DIR="$SCRIPT_DIR/release"

echo "==> Creating release $VERSION on clampd/clampd"
echo ""

# ── 1. Prepare release artifacts ─────────────────────────────
echo "[1/3] Preparing artifacts..."
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

# CLI binary
CLI_BIN="$SCRIPT_DIR/bin/clampd-${VERSION}-linux-amd64"
if [[ ! -f "$CLI_BIN" ]]; then
    # Try without 'v' prefix
    CLI_BIN="$SCRIPT_DIR/bin/clampd-v${VERSION#v}-linux-amd64"
fi
if [[ -f "$CLI_BIN" ]]; then
    cp "$CLI_BIN" "$RELEASE_DIR/clampd-linux-amd64"
    chmod +x "$RELEASE_DIR/clampd-linux-amd64"
    tar -czf "$RELEASE_DIR/clampd-linux-amd64.tar.gz" -C "$RELEASE_DIR" clampd-linux-amd64
    rm "$RELEASE_DIR/clampd-linux-amd64"
    echo "  clampd CLI: $(du -h "$RELEASE_DIR/clampd-linux-amd64.tar.gz" | cut -f1)"
else
    echo "  WARN: CLI binary not found at $CLI_BIN - skipping"
fi

# Guard binary
GUARD_BIN="$SCRIPT_DIR/bin/clampd-guard-${VERSION}-linux-amd64"
if [[ ! -f "$GUARD_BIN" ]]; then
    GUARD_BIN="$SCRIPT_DIR/bin/clampd-guard-v${VERSION#v}-linux-amd64"
fi
if [[ -f "$GUARD_BIN" ]]; then
    cp "$GUARD_BIN" "$RELEASE_DIR/clampd-guard-linux-amd64"
    chmod +x "$RELEASE_DIR/clampd-guard-linux-amd64"
    tar -czf "$RELEASE_DIR/clampd-guard-linux-amd64.tar.gz" -C "$RELEASE_DIR" clampd-guard-linux-amd64
    rm "$RELEASE_DIR/clampd-guard-linux-amd64"
    echo "  clampd-guard: $(du -h "$RELEASE_DIR/clampd-guard-linux-amd64.tar.gz" | cut -f1)"
else
    echo "  WARN: Guard binary not found at $GUARD_BIN - skipping"
fi

# Compose files + setup script
cp "$SCRIPT_DIR/docker/docker-compose.proxy.yml" "$RELEASE_DIR/"
cp "$SCRIPT_DIR/docker/docker-compose.control.yml" "$RELEASE_DIR/"
cp "$SCRIPT_DIR/docker/.env.example" "$RELEASE_DIR/"
cp "$SCRIPT_DIR/docker/setup.sh" "$RELEASE_DIR/"

# Checksums
cd "$RELEASE_DIR"
sha256sum *.tar.gz *.yml *.sh 2>/dev/null > SHA256SUMS.txt
cd "$SCRIPT_DIR"

echo "  Artifacts ready:"
ls -lh "$RELEASE_DIR/"
echo ""

# ── 2. Create release ────────────────────────────────────────
echo "[2/3] Creating GitHub release..."

gh release create "$VERSION" \
    --repo clampd/clampd \
    --title "Clampd $VERSION" \
    --notes "$(cat <<'EOF'
## Install

**Docker - Proxy (security pipeline):**
```bash
curl -sL https://github.com/clampd/clampd/raw/main/docker/docker-compose.proxy.yml -o docker-compose.yml
curl -sL https://github.com/clampd/clampd/raw/main/docker/setup.sh | sh
# Set CLAMPD_LICENSE_KEY in .env (get one at https://app.clampd.dev)
docker compose --profile local-infra up -d
```

**Docker - Dashboard (control plane):**
```bash
curl -sL https://github.com/clampd/clampd/raw/main/docker/docker-compose.control.yml -o docker-compose.control.yml
docker compose -f docker-compose.control.yml --profile local-infra up -d
```

**CLI:**
```bash
curl -fsSL https://clampd.dev/install.sh | sh
```

**Claude Code / Cursor guard:**
```bash
curl -fsSL https://clampd.dev/install-guard.sh | sh
clampd-guard setup --url https://your-gateway:8080 --key KEY --agent AGENT --secret SECRET
```

**SDKs:**
```bash
pip install clampd          # Python
npm install @clampd/sdk     # TypeScript
```

## Docker Images

All images at `ghcr.io/clampd/*:v0.9.0`

| Image | Service |
|---|---|
| `ghcr.io/clampd/ag-gateway` | HTTP gateway, 9-stage pipeline |
| `ghcr.io/clampd/ag-intent` | Classification, 152 detection rules |
| `ghcr.io/clampd/ag-policy` | Policy engine, scope exemptions |
| `ghcr.io/clampd/ag-risk` | Anomaly detection, EMA scoring |
| `ghcr.io/clampd/ag-shadow` | Audit pipeline, PII masking |
| `ghcr.io/clampd/ag-kill` | Kill cascade, auto-suspend |
| `ghcr.io/clampd/ag-registry` | Agent lifecycle |
| `ghcr.io/clampd/ag-token` | Token exchange |
| `ghcr.io/clampd/ag-control` | SaaS bridge, API key sync |
| `ghcr.io/clampd/dashboard-api` | Dashboard API |
| `ghcr.io/clampd/dashboard-web` | Dashboard UI |
| `ghcr.io/clampd/mcp-proxy` | MCP server security wrapper |

## Checksums

See `SHA256SUMS.txt` for verification.
EOF
)" \
    "$RELEASE_DIR/clampd-linux-amd64.tar.gz" \
    "$RELEASE_DIR/clampd-guard-linux-amd64.tar.gz" \
    "$RELEASE_DIR/docker-compose.proxy.yml" \
    "$RELEASE_DIR/docker-compose.control.yml" \
    "$RELEASE_DIR/.env.example" \
    "$RELEASE_DIR/setup.sh" \
    "$RELEASE_DIR/SHA256SUMS.txt"

echo ""
echo "[3/3] Done!"
echo ""
echo "  Release: https://github.com/clampd/clampd/releases/tag/$VERSION"
echo ""
echo "  Next steps:"
echo "    1. Make GHCR packages public: github.com/orgs/clampd/packages"
echo "    2. Verify: docker pull ghcr.io/clampd/ag-gateway:$VERSION"
echo "    3. Verify: curl -fsSL https://clampd.dev/install.sh | sh"
