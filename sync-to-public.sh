#!/bin/bash
# sync-to-public.sh - Selective sync: private repo → public distribution repo
#
# What ships publicly:
#   1. SDKs (full source, Apache 2.0)        - Python + TypeScript
#   2. clampd-guard (full source, BSL 1.1)   - Claude Code / Cursor hook
#   3. ag-gateway (partial source, BSL 1.1)  - request pipeline (no detection IP)
#   4. ag-shadow (full source, BSL 1.1)      - audit pipeline + PII masker
#   5. Proto (full, Apache 2.0)              - gRPC API contracts
#   6. Docker compose + config               - deployment files
#   7. Pre-built binaries                    - clampd CLI + clampd-guard
#
# Everything else ships as Docker images only (ghcr.io/clampd/*).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_ROOT="$(dirname "$SCRIPT_DIR")"
PUBLIC_ROOT="$SCRIPT_DIR"
SVC="$PRIVATE_ROOT/services/crates"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true && echo "[DRY RUN]"

VERSION="${CLAMPD_VERSION:-0.9.0}"
echo "==> Syncing Clampd v${VERSION}"

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

# ── 1. SDKs (Apache 2.0 - full source) ──────────────────────
echo "[1/7] SDKs"
copy_dir "$PRIVATE_ROOT/sdk/python" "$PUBLIC_ROOT/sdk/python"
copy_dir "$PRIVATE_ROOT/sdk/typescript" "$PUBLIC_ROOT/sdk/typescript"
if ! $DRY_RUN; then
    rm -f "$PUBLIC_ROOT/sdk/python/"{package.json,package-lock.json,test_sdk_e2e.py}
    rm -f "$PUBLIC_ROOT/sdk/typescript/"{clampd-0.3.0.tgz,test_quote}
    rm -f "$PUBLIC_ROOT/sdk/typescript/examples/test_clean.ts"
    find "$PUBLIC_ROOT/sdk" \( -name '.env' -o -name '.env.local' -o -name '.env.backup' \) -delete 2>/dev/null || true
fi

# ── 2. Proto (Apache 2.0 - full) ────────────────────────────
echo "[2/7] Proto"
copy_dir "$PRIVATE_ROOT/proto" "$PUBLIC_ROOT/proto"

# ── 3. Docker (Apache 2.0 - deployment files only) ──────────
echo "[3/7] Docker"
if ! $DRY_RUN; then
    mkdir -p "$PUBLIC_ROOT/docker"
    cp "$PRIVATE_ROOT/clampd/docker-compose.proxy.yml" "$PUBLIC_ROOT/docker/" 2>/dev/null || true
    cp "$PRIVATE_ROOT/clampd/docker-compose.control.yml" "$PUBLIC_ROOT/docker/" 2>/dev/null || true
    cp "$PRIVATE_ROOT/clampd/.env.example" "$PUBLIC_ROOT/docker/" 2>/dev/null || true
    cp "$PRIVATE_ROOT/sdk/typescript/mcp-proxy/Dockerfile" "$PUBLIC_ROOT/docker/mcp-proxy.Dockerfile" 2>/dev/null || true

    # Remove dev-only files
    rm -f "$PUBLIC_ROOT/docker/docker-compose.yml" 2>/dev/null || true
    rm -f "$PUBLIC_ROOT/docker/docker-compose.deploy.yml" 2>/dev/null || true

    # Strip redteam from proxy compose
    if [[ -f "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" ]]; then
        sed -i '/# ── Red Team Testing/,/# ── Reverse Proxy/{/# ── Reverse Proxy/!d}' \
            "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" 2>/dev/null || true
        sed -i '/^\s*build:/,/^\s*dockerfile:/d' \
            "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" 2>/dev/null || true
        sed -i '/CLAMPD_DEMO_PANEL/d' \
            "$PUBLIC_ROOT/docker/docker-compose.proxy.yml" 2>/dev/null || true
    fi
fi

# ── 4. ag-gateway (BSL 1.1 - partial: pipeline, no detection IP) ──
echo "[4/7] ag-gateway (partial - 15 pipeline files)"
copy_files "$SVC/ag-gateway/src" "$PUBLIC_ROOT/src/ag-gateway" \
    main.rs proxy.rs middleware.rs extractor.rs normalize.rs \
    decision.rs delegation.rs scan.rs shadow.rs session.rs \
    metrics.rs otel.rs scope_token.rs rate_limiter.rs circuit_breaker.rs
$DRY_RUN || cp "$SVC/ag-gateway/Cargo.toml" "$PUBLIC_ROOT/src/ag-gateway/"

# ── 5. ag-shadow (BSL 1.1 - full: audit pipeline + PII masker) ──
echo "[5/7] ag-shadow (full - data handling transparency)"
copy_files "$SVC/ag-shadow/src" "$PUBLIC_ROOT/src/ag-shadow" \
    main.rs consumer.rs writer.rs pii_masker.rs enricher.rs lib.rs
$DRY_RUN || cp "$SVC/ag-shadow/Cargo.toml" "$PUBLIC_ROOT/src/ag-shadow/"

# ── 6. clampd-guard (BSL 1.1 - full source + tests) ─────────
echo "[6/7] clampd-guard (full source)"
if ! $DRY_RUN; then
    mkdir -p "$PUBLIC_ROOT/src/clampd-guard/src" "$PUBLIC_ROOT/src/clampd-guard/tests"
    cp "$SVC/clampd-guard/Cargo.toml" "$PUBLIC_ROOT/src/clampd-guard/"
    cp "$SVC/clampd-guard/src/"*.rs "$PUBLIC_ROOT/src/clampd-guard/src/"
    cp "$SVC/clampd-guard/tests/"*.rs "$PUBLIC_ROOT/src/clampd-guard/tests/" 2>/dev/null || true
fi

# ── 7. Binaries ──────────────────────────────────────────────
echo "[7/7] Binaries"
if ! $DRY_RUN; then
    mkdir -p "$PUBLIC_ROOT/bin"

    # clampd CLI
    CLI_BIN="$PRIVATE_ROOT/services/target/release/clampd"
    if [[ ! -f "$CLI_BIN" ]]; then
        echo "    Building clampd CLI..."
        (cd "$PRIVATE_ROOT/services" && cargo build --release --bin clampd -p clampd-cli 2>&1 | tail -3)
    fi
    if [[ -f "$CLI_BIN" ]]; then
        cp "$CLI_BIN" "$PUBLIC_ROOT/bin/clampd-v${VERSION}-linux-amd64"
        chmod +x "$PUBLIC_ROOT/bin/clampd-v${VERSION}-linux-amd64"
        echo "    clampd CLI: bin/clampd-v${VERSION}-linux-amd64 ($(du -h "$PUBLIC_ROOT/bin/clampd-v${VERSION}-linux-amd64" | cut -f1))"
    else
        echo "    ERROR: clampd CLI build failed"
        exit 1
    fi

    # clampd-guard
    GUARD_BIN="$PRIVATE_ROOT/services/target/release/clampd-guard"
    if [[ ! -f "$GUARD_BIN" ]]; then
        echo "    Building clampd-guard..."
        (cd "$PRIVATE_ROOT/services" && cargo build --release --bin clampd-guard -p clampd-guard 2>&1 | tail -3)
    fi
    if [[ -f "$GUARD_BIN" ]]; then
        cp "$GUARD_BIN" "$PUBLIC_ROOT/bin/clampd-guard-v${VERSION}-linux-amd64"
        chmod +x "$PUBLIC_ROOT/bin/clampd-guard-v${VERSION}-linux-amd64"
        echo "    clampd-guard: bin/clampd-guard-v${VERSION}-linux-amd64 ($(du -h "$PUBLIC_ROOT/bin/clampd-guard-v${VERSION}-linux-amd64" | cut -f1))"
    else
        echo "    WARN: clampd-guard build failed (non-fatal)"
    fi
fi

# ── Verify - leak scanner ───────────────────────────────────
echo ""
echo "Verifying (deep scan)..."
LEAKED=false

# Must NOT exist in public repo
for bad in ag-license ag-redteam integration-tests ag-engine ag-intent ag-policy \
           ag-risk ag-kill ag-registry ag-control ag-token ag-common ag-proto clampd-cli; do
    for check_dir in "$PUBLIC_ROOT/services/crates/$bad" "$PUBLIC_ROOT/src/$bad"; do
        # ag-gateway and ag-shadow are allowed in src/
        [[ "$bad" == "ag-gateway" || "$bad" == "ag-shadow" ]] && [[ "$check_dir" == "$PUBLIC_ROOT/src/$bad" ]] && continue
        if [[ -e "$check_dir" ]]; then
            echo "  WARN: excluded service '$bad' found at $check_dir!"
            LEAKED=true
        fi
    done
done

# Old services/ directory should not have crates
if [[ -d "$PUBLIC_ROOT/services/crates" ]]; then
    echo "  WARN: old services/crates/ directory still exists - remove it!"
    LEAKED=true
fi

# RSA private key - CRITICAL
PRIV_KEYS=$(find "$PUBLIC_ROOT" -name "*priv*" -o -name "private*.pem" 2>/dev/null || true)
if [[ -n "$PRIV_KEYS" ]]; then
    echo "  CRITICAL: RSA private key found!"
    echo "  $PRIV_KEYS"
    LEAKED=true
fi

# .env files (except .env.example)
ENV_FILES=$(find "$PUBLIC_ROOT" -name '.env' -not -name '.env.example' 2>/dev/null || true)
[[ -n "$ENV_FILES" ]] && echo "  WARN: .env files: $ENV_FILES" && LEAKED=true

# Secrets scan
SECRETS=$(grep -rn \
    -e 'ag_test_\|ags_[a-f0-9]\{16,\}\|sk-[a-zA-Z0-9]\{20,\}' \
    -e 'PRIVATE KEY' \
    -e 'password\s*=\s*"[^"]\{8,\}"' \
    --include='*.rs' --include='*.toml' --include='*.yml' --include='*.json' --include='*.py' --include='*.ts' \
    "$PUBLIC_ROOT/src" "$PUBLIC_ROOT/docker" "$PUBLIC_ROOT/sdk" 2>/dev/null \
    | grep -v 'test\|example\|mock\|fixture\|\.env\.example\|password.*clampd\|POSTGRES_PASSWORD\|detect_secrets\|EXAMPLE\|BEGIN.*PRIVATE.*comment\|/// ' \
    || true)
if [[ -n "$SECRETS" ]]; then
    echo "  WARN: Possible secrets found:"
    echo "$SECRETS" | head -5
    LEAKED=true
fi

# No private directories
for unexpected in dashboard deploy terraform .claude memory documents license-service; do
    if [[ -e "$PUBLIC_ROOT/$unexpected" ]]; then
        echo "  WARN: unexpected directory '$unexpected' in public repo!"
        LEAKED=true
    fi
done

# .rs file count - should be low (guard:8, gateway:15, shadow:6 + tests)
RS_COUNT=$(find "$PUBLIC_ROOT/src" -name "*.rs" -type f 2>/dev/null | wc -l)
if [[ "$RS_COUNT" -gt 50 ]]; then
    echo "  WARN: ${RS_COUNT} .rs files in src/ - expected ~30, possible leak"
    LEAKED=true
fi

$LEAKED && echo "  ABORT: Fix issues before pushing." && exit 1
echo "  OK - clean (${RS_COUNT} .rs files in src/)"

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "==> Done! v${VERSION}"
echo ""
echo "  OPEN SOURCE:"
echo "    sdk/python/             Python SDK (Apache 2.0)"
echo "    sdk/typescript/         TypeScript SDK (Apache 2.0)"
echo "    src/clampd-guard/       Claude Code & Cursor guard - full source (BSL 1.1)"
echo "    src/ag-gateway/         Request pipeline - 15 files, partial (BSL 1.1)"
echo "    src/ag-shadow/          Audit + PII masking - full source (BSL 1.1)"
echo "    proto/                  gRPC contracts (Apache 2.0)"
echo ""
echo "  BINARY ONLY (Docker images at ghcr.io/clampd/*):"
echo "    ag-engine, ag-intent, ag-policy, ag-risk, ag-kill,"
echo "    ag-registry, ag-token, ag-control, dashboard"
echo ""
echo "  PRE-BUILT BINARIES:"
echo "    bin/clampd-v${VERSION}-linux-amd64"
echo "    bin/clampd-guard-v${VERSION}-linux-amd64"
