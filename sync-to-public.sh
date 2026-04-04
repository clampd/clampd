#!/bin/bash
# sync-to-public.sh - Selective sync: private repo → public repo
#
# Selective sync with stubs for proprietary rule content.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_ROOT="$(dirname "$SCRIPT_DIR")"
PUBLIC_ROOT="$SCRIPT_DIR"
STUBS_DIR="$SCRIPT_DIR/stubs"
SVC="$PRIVATE_ROOT/services/crates"
PUB_SVC="$PUBLIC_ROOT/services/crates"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true && echo "[DRY RUN]"

VERSION="${CLAMPD_VERSION:-0.8.0}"
echo "==> Syncing Clampd v${VERSION} (selective)"

copy_dir() {
    $DRY_RUN && echo "  [dry-run] $1 -> $2" && return
    mkdir -p "$2"
    rsync -a --delete --exclude='.env' --exclude='.env.*' --exclude='!.env.example' \
        --exclude='node_modules/' --exclude='dist/' --exclude='__pycache__/' \
        --exclude='*.egg-info/' --exclude='.venv/' --exclude='.pytest_cache/' \
        --exclude='.ruff_cache/' --exclude='*.tgz' --exclude='test_quote' --quiet "$1/" "$2/"
}

copy_files() {
    local src_dir="$1" dst_dir="$2"; shift 2
    $DRY_RUN && echo "  [dry-run] $src_dir/{$*} -> $dst_dir" && return
    mkdir -p "$dst_dir"
    for f in "$@"; do cp "$src_dir/$f" "$dst_dir/" 2>/dev/null || true; done
}

# ── 1. SDKs (Apache 2.0 - full) ─────────────────────────────
echo "[1/8] SDKs (Python + TypeScript only)"
copy_dir "$PRIVATE_ROOT/sdk/python" "$PUBLIC_ROOT/sdk/python"
copy_dir "$PRIVATE_ROOT/sdk/typescript" "$PUBLIC_ROOT/sdk/typescript"
if ! $DRY_RUN; then
    rm -f "$PUBLIC_ROOT/sdk/python/"{package.json,package-lock.json,test_sdk_e2e.py}
    rm -f "$PUBLIC_ROOT/sdk/typescript/"{clampd-0.3.0.tgz,test_quote}
    rm -f "$PUBLIC_ROOT/sdk/typescript/examples/test_clean.ts"
    find "$PUBLIC_ROOT/sdk" \( -name '.env' -o -name '.env.local' -o -name '.env.backup' \) -delete 2>/dev/null || true
fi

# ── 2. Proto (Apache 2.0 - full) ────────────────────────────
echo "[2/8] Proto"
copy_dir "$PRIVATE_ROOT/proto" "$PUBLIC_ROOT/proto"

# ── 3. Docker (Apache 2.0) - clean customer-facing files ────
echo "[3/8] Docker"
if ! $DRY_RUN; then
    mkdir -p "$PUBLIC_ROOT/docker/services"
    # Only ship the customer-facing compose files (proxy + control)
    # NOT docker-compose.yml (dev-only, references demo seeds/mock-tool)
    cp "$PRIVATE_ROOT/clampd/docker-compose.proxy.yml" "$PUBLIC_ROOT/docker/" 2>/dev/null || true
    cp "$PRIVATE_ROOT/clampd/docker-compose.control.yml" "$PUBLIC_ROOT/docker/" 2>/dev/null || true
    cp "$PRIVATE_ROOT/clampd/.env.example" "$PUBLIC_ROOT/docker/" 2>/dev/null || true
    # Caddyfile excluded - users configure their own reverse proxy
    cp "$PRIVATE_ROOT/services/deploy/Dockerfile.service" "$PUBLIC_ROOT/docker/services/" 2>/dev/null || true
    cp "$PRIVATE_ROOT/sdk/typescript/mcp-proxy/Dockerfile" "$PUBLIC_ROOT/docker/mcp-proxy.Dockerfile" 2>/dev/null || true

    # Remove dev-only compose (references demo seeds, mock-tool)
    rm -f "$PUBLIC_ROOT/docker/docker-compose.yml" 2>/dev/null || true
    rm -f "$PUBLIC_ROOT/docker/docker-compose.deploy.yml" 2>/dev/null || true

    # Strip redteam + MCP + fleet from proxy compose (they're in docker-compose.demo.yml)
    if [[ -f "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" ]]; then
        # Remove everything from "Red Team Testing" to "Reverse Proxy"
        sed -i '/# ── Red Team Testing/,/# ── Reverse Proxy/{/# ── Reverse Proxy/!d}' \
            "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" 2>/dev/null || true
        # Remove any build: context blocks
        sed -i '/^\s*build:/,/^\s*dockerfile:/d' \
            "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" 2>/dev/null || true
        # Remove CLAMPD_DEMO_PANEL
        sed -i '/CLAMPD_DEMO_PANEL/d' \
            "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" 2>/dev/null || true
    fi
fi

# ── 4. ag-gateway ──────────
echo "[4/8] ag-gateway (pipeline)"
copy_files "$SVC/ag-gateway/src" "$PUB_SVC/ag-gateway/src" \
    main.rs proxy.rs middleware.rs extractor.rs normalize.rs \
    decision.rs delegation.rs scan.rs shadow.rs session.rs \
    metrics.rs otel.rs scope_token.rs rate_limiter.rs circuit_breaker.rs
$DRY_RUN || cp "$SVC/ag-gateway/Cargo.toml" "$PUB_SVC/ag-gateway/"

# ── 5. ag-engine ─────
echo "[5/8] ag-engine (open modules + stubs)"
if ! $DRY_RUN; then
    # lib.rs
    mkdir -p "$PUB_SVC/ag-engine/src"
    cp "$SVC/ag-engine/Cargo.toml" "$PUB_SVC/ag-engine/"
    cp "$SVC/ag-engine/src/lib.rs" "$PUB_SVC/ag-engine/src/"


    for dir in parse compile execute normalize funnel scheme storage taxonomy versioning testing; do
        if [[ -d "$SVC/ag-engine/src/$dir" ]]; then
            mkdir -p "$PUB_SVC/ag-engine/src/$dir"
            cp "$SVC/ag-engine/src/$dir/"*.rs "$PUB_SVC/ag-engine/src/$dir/" 2>/dev/null || true
        fi
    done

    # Signals
    mkdir -p "$PUB_SVC/ag-engine/src/signals"
    cp "$STUBS_DIR/signals/mod.rs" "$PUB_SVC/ag-engine/src/signals/mod.rs"

    # Dictionary
    mkdir -p "$PUB_SVC/ag-engine/src/dictionary"
    cp "$STUBS_DIR/dictionary/mod.rs" "$PUB_SVC/ag-engine/src/dictionary/mod.rs"

    # Builtins
    mkdir -p "$PUB_SVC/ag-engine/src/builtins"
    cp "$STUBS_DIR/builtins/mod.rs" "$PUB_SVC/ag-engine/src/builtins/mod.rs"

    # Compliance
    mkdir -p "$PUB_SVC/ag-engine/src/compliance"
    cp "$STUBS_DIR/compliance/mod.rs" "$PUB_SVC/ag-engine/src/compliance/mod.rs"
fi

# ── 6. ag-shadow ─────
echo "[6/8] ag-shadow (audit pipeline)"
copy_files "$SVC/ag-shadow/src" "$PUB_SVC/ag-shadow/src" \
    main.rs consumer.rs writer.rs pii_masker.rs enricher.rs lib.rs
$DRY_RUN || cp "$SVC/ag-shadow/Cargo.toml" "$PUB_SVC/ag-shadow/"

# ── 7. Supporting services (entry points only) ──────────────
echo "[7/8] Supporting services (shells)"

# ag-common
copy_dir "$SVC/ag-common" "$PUB_SVC/ag-common"

$DRY_RUN || rm -f "$PUB_SVC/ag-common/src/license_guard.rs" "$PUB_SVC/ag-common/src/license.rs"

# ag-proto
if ! $DRY_RUN; then
    mkdir -p "$PUB_SVC/ag-proto/src"
    cp "$SVC/ag-proto/Cargo.toml" "$PUB_SVC/ag-proto/"
    cp "$SVC/ag-proto/build.rs" "$PUB_SVC/ag-proto/" 2>/dev/null || true
    cp "$SVC/ag-proto/src/lib.rs" "$PUB_SVC/ag-proto/src/"
fi

# ag-policy
copy_files "$SVC/ag-policy/src" "$PUB_SVC/ag-policy/src" \
    main.rs service.rs decision.rs lib.rs
$DRY_RUN || cp "$SVC/ag-policy/Cargo.toml" "$PUB_SVC/ag-policy/"

# ag-risk
copy_files "$SVC/ag-risk/src" "$PUB_SVC/ag-risk/src" \
    main.rs service.rs scorer.rs baseline.rs lib.rs
$DRY_RUN || cp "$SVC/ag-risk/Cargo.toml" "$PUB_SVC/ag-risk/"

# ag-intent
copy_files "$SVC/ag-intent/src" "$PUB_SVC/ag-intent/src" \
    main.rs service.rs lib.rs
$DRY_RUN || cp "$SVC/ag-intent/Cargo.toml" "$PUB_SVC/ag-intent/"

# ag-token
copy_files "$SVC/ag-token/src" "$PUB_SVC/ag-token/src" \
    main.rs service.rs lib.rs signing.rs exchange.rs
$DRY_RUN || cp "$SVC/ag-token/Cargo.toml" "$PUB_SVC/ag-token/"

# ag-kill
copy_files "$SVC/ag-kill/src" "$PUB_SVC/ag-kill/src" \
    main.rs service.rs cascade.rs
$DRY_RUN || cp "$SVC/ag-kill/Cargo.toml" "$PUB_SVC/ag-kill/"

# ag-registry
copy_files "$SVC/ag-registry/src" "$PUB_SVC/ag-registry/src" \
    main.rs service.rs lifecycle.rs repository.rs lib.rs
$DRY_RUN || cp "$SVC/ag-registry/Cargo.toml" "$PUB_SVC/ag-registry/"

# ag-control
copy_files "$SVC/ag-control/src" "$PUB_SVC/ag-control/src" \
    main.rs service.rs poller.rs health.rs leader.rs
$DRY_RUN || cp "$SVC/ag-control/Cargo.toml" "$PUB_SVC/ag-control/"

# clampd-cli
if ! $DRY_RUN; then
    mkdir -p "$PUB_SVC/clampd-cli/src/commands"
    cp "$SVC/clampd-cli/Cargo.toml" "$PUB_SVC/clampd-cli/"
    copy_files "$SVC/clampd-cli/src" "$PUB_SVC/clampd-cli/src" \
        main.rs config.rs output.rs state.rs
    for f in "$SVC/clampd-cli/src/commands/"*.rs; do
        fname="$(basename "$f")"
        [[ "$fname" == "demo.rs" ]] && continue
        cp "$f" "$PUB_SVC/clampd-cli/src/commands/"
    done
    rm -f "$PUB_SVC/clampd-cli/src/license_gate.rs"
fi

# Workspace Cargo files
$DRY_RUN || cp "$PRIVATE_ROOT/services/Cargo.toml" "$PUBLIC_ROOT/services/" 2>/dev/null || true
$DRY_RUN || cp "$PRIVATE_ROOT/services/Cargo.lock" "$PUBLIC_ROOT/services/" 2>/dev/null || true

# CLI binary - build if needed, copy with version
if ! $DRY_RUN; then
    CLI_BIN="$PRIVATE_ROOT/services/target/release/clampd"
    if [[ ! -f "$CLI_BIN" ]]; then
        echo "    Building CLI binary..."
        (cd "$PRIVATE_ROOT/services" && cargo build --release --bin clampd -p clampd-cli 2>&1 | tail -3)
    fi
    if [[ -f "$CLI_BIN" ]]; then
        mkdir -p "$PUBLIC_ROOT/bin"
        cp "$CLI_BIN" "$PUBLIC_ROOT/bin/clampd-v${VERSION}-linux-amd64"
        chmod +x "$PUBLIC_ROOT/bin/clampd-v${VERSION}-linux-amd64"
        echo "    CLI binary: bin/clampd-v${VERSION}-linux-amd64 ($(du -h "$PUBLIC_ROOT/bin/clampd-v${VERSION}-linux-amd64" | cut -f1))"
    else
        echo "    ERROR: CLI build failed"
        exit 1
    fi
fi

# ── 8. Verify - audit the auditor ────────────────────────────
echo "[8/8] Verifying (deep scan)"
LEAKED=false

# Known bad directories
for bad in ag-license ag-redteam integration-tests; do
    [[ -e "$PUB_SVC/$bad" ]] && echo "  WARN: excluded service '$bad' found!" && LEAKED=true
done

# Known bad files
[[ -d "$PUB_SVC/ag-engine/src/builtins/rules" ]] && echo "  WARN: Rule TOML files leaked!" && LEAKED=true
[[ -f "$PUB_SVC/clampd-cli/src/license_gate.rs" ]] && echo "  WARN: license_gate.rs leaked!" && LEAKED=true
[[ -f "$PUB_SVC/ag-common/src/license_guard.rs" ]] && echo "  WARN: license_guard.rs leaked!" && LEAKED=true
[[ -f "$PUB_SVC/ag-common/src/license.rs" ]] && echo "  WARN: license.rs leaked!" && LEAKED=true
[[ -f "$PUB_SVC/clampd-cli/src/commands/demo.rs" ]] && echo "  WARN: demo.rs leaked!" && LEAKED=true

# .env files (except .env.example)
ENV_FILES=$(find "$PUBLIC_ROOT" -name '.env' -not -name '.env.example' 2>/dev/null || true)
[[ -n "$ENV_FILES" ]] && echo "  WARN: .env files: $ENV_FILES" && LEAKED=true

# Secrets pattern scan - grep for anything that looks like a real key/token/password
SECRETS=$(grep -rn \
    -e 'ag_test_\|ags_[a-f0-9]\{16,\}\|sk-[a-zA-Z0-9]\{20,\}' \
    -e 'PRIVATE KEY' \
    -e 'password\s*=\s*"[^"]\{8,\}"' \
    --include='*.rs' --include='*.toml' --include='*.yml' --include='*.json' --include='*.py' --include='*.ts' \
    "$PUBLIC_ROOT/services" "$PUBLIC_ROOT/docker" 2>/dev/null \
    | grep -v 'test\|example\|mock\|fixture\|\.env\.example\|password.*clampd\|POSTGRES_PASSWORD\|detect_secrets\|EXAMPLE\|BEGIN.*PRIVATE.*comment\|/// ' \
    || true)
if [[ -n "$SECRETS" ]]; then
    echo "  WARN: Possible secrets found:"
    echo "$SECRETS" | head -5
    LEAKED=true
fi

# Check no private directories leaked that we didn't expect
for unexpected in dashboard deploy terraform .claude memory documents; do
    if [[ -e "$PUBLIC_ROOT/$unexpected" ]]; then
        echo "  WARN: unexpected directory '$unexpected' in public repo!"
        LEAKED=true
    fi
done

# Count check - if we suddenly have way more .rs files than expected, something is wrong
RS_COUNT=$(find "$PUBLIC_ROOT/services" -name "*.rs" -type f 2>/dev/null | wc -l)
if [[ "$RS_COUNT" -gt 200 ]]; then
    echo "  WARN: ${RS_COUNT} .rs files - expected ~120, possible full-copy leak"
    LEAKED=true
fi

$LEAKED && echo "  ABORT: Fix issues before pushing." && exit 1
echo "  OK - clean (${RS_COUNT} .rs files)"

# ── Summary ──────────────────────────────────────────────────
RS_COUNT=$(find "$PUBLIC_ROOT/services" -name "*.rs" -type f 2>/dev/null | wc -l)
echo ""
echo "==> Done! v${VERSION} - ${RS_COUNT} .rs files"
echo ""
echo "  OPEN (full source):     SDKs, proto, docker, ag-common, signals"
echo "  OPEN (data path):       ag-gateway(15), ag-shadow(6), ag-engine modules"
echo "  OPEN (service shells):  ag-policy, ag-risk, ag-intent, ag-token, ag-kill,"
echo "                          ag-registry, ag-control, clampd-cli"
echo "  STUBBED (interface):    builtins(rules), dictionary(keywords), compliance(mappings)"
echo "  EXCLUDED:               dashboard, deploy, ag-license, ag-redteam, integration-tests"
