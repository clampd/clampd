#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────
# Clampd License Generator
#
# Generates RSA-4096 signed JWT license tokens for Design Partner and
# Enterprise plans.
#
# Prerequisites: openssl, python3 (with PyJWT: pip install PyJWT)
#
# Usage:
#   ./generate-license.sh init                      # One-time: generate RSA-4096 keypair
#   ./generate-license.sh design_partner <org_id>   # Generate Design Partner license
#   ./generate-license.sh enterprise <org_id>       # Generate Enterprise license
#   ./generate-license.sh custom <org_id> <json>    # Generate with custom overrides
#   ./generate-license.sh decode <token>            # Decode and inspect a license
#   ./generate-license.sh list                      # List all issued licenses
#
# Examples:
#   ./generate-license.sh init
#   ./generate-license.sh design_partner acme-corp
#   ./generate-license.sh design_partner acme-corp 365        # 365 day expiry
#   ./generate-license.sh enterprise big-co 730               # 2 year enterprise
#   ./generate-license.sh custom acme-corp '{"max_agents":50,"max_requests_per_month":100000}'
#   ./generate-license.sh decode eyJhbGci...
# ───────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${SCRIPT_DIR}/.license-keys"
LICENSES_DIR="${SCRIPT_DIR}/.licenses"

# Feature flag bits (must match ag-license/src/guard.rs FeatureFlags)
FEAT_DASHBOARD=1           # 1 << 0
FEAT_SSO=2                 # 1 << 1
FEAT_COMPLIANCE_EXPORT=4   # 1 << 2
FEAT_RBAC=8                # 1 << 3
FEAT_A2A=16                # 1 << 4
FEAT_WEBHOOKS=32           # 1 << 5
FEAT_PII_QUARANTINE=64     # 1 << 6
FEAT_SCOPE_PERMISSIONS=128 # 1 << 7
FEAT_ANOMALY_DETECTION=256 # 1 << 8

# Plan defaults
DESIGN_PARTNER_FEATURES=$((FEAT_DASHBOARD | FEAT_ANOMALY_DETECTION))  # 257
ENTERPRISE_FEATURES=$(( FEAT_DASHBOARD | FEAT_SSO | FEAT_COMPLIANCE_EXPORT | FEAT_RBAC | FEAT_A2A | FEAT_WEBHOOKS | FEAT_PII_QUARANTINE | FEAT_SCOPE_PERMISSIONS | FEAT_ANOMALY_DETECTION ))  # 511 (all)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; }

# ── init: Generate RSA-4096 keypair ──────────────────────────────────

cmd_init() {
    mkdir -p "$KEYS_DIR"

    if [[ -f "$KEYS_DIR/private.pem" ]]; then
        warn "Keypair already exists at $KEYS_DIR/"
        echo "  Private: $KEYS_DIR/private.pem"
        echo "  Public:  $KEYS_DIR/public.pem"
        read -rp "Regenerate? This will INVALIDATE all existing licenses. [y/N] " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            info "Keeping existing keypair."
            return 0
        fi
        # Backup old keys
        mv "$KEYS_DIR/private.pem" "$KEYS_DIR/private.pem.bak.$(date +%s)"
        mv "$KEYS_DIR/public.pem" "$KEYS_DIR/public.pem.bak.$(date +%s)"
    fi

    info "Generating RSA-4096 keypair..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
        -out "$KEYS_DIR/private.pem" 2>/dev/null
    openssl rsa -in "$KEYS_DIR/private.pem" -pubout \
        -out "$KEYS_DIR/public.pem" 2>/dev/null
    chmod 600 "$KEYS_DIR/private.pem"
    chmod 644 "$KEYS_DIR/public.pem"

    info "Keypair generated:"
    echo "  Private: $KEYS_DIR/private.pem (keep this SECRET)"
    echo "  Public:  $KEYS_DIR/public.pem  (bake into binaries)"
    echo ""
    info "Next steps:"
    echo "  1. Copy public.pem into services/crates/ag-license/src/key.rs (obfuscated)"
    echo "  2. NEVER commit private.pem to git"
    echo "  3. Generate licenses: ./generate-license.sh design_partner <org_id>"

    # Add to .gitignore if not already there
    if [[ -f "$SCRIPT_DIR/.gitignore" ]]; then
        if ! grep -q ".license-keys" "$SCRIPT_DIR/.gitignore" 2>/dev/null; then
            echo ".license-keys/" >> "$SCRIPT_DIR/.gitignore"
            info "Added .license-keys/ to .gitignore"
        fi
    else
        echo ".license-keys/" > "$SCRIPT_DIR/.gitignore"
        echo ".licenses/" >> "$SCRIPT_DIR/.gitignore"
        info "Created .gitignore with .license-keys/ and .licenses/"
    fi
}

# ── Generate license JWT ─────────────────────────────────────────────

generate_license() {
    local plan="$1"
    local org_id="$2"
    local expiry_days="${3:-180}"  # Default 180 days
    local custom_limits="${4:-}"

    if [[ ! -f "$KEYS_DIR/private.pem" ]]; then
        error "No keypair found. Run './generate-license.sh init' first."
        exit 1
    fi

    # Validate plan
    if [[ "$plan" != "design_partner" && "$plan" != "enterprise" ]]; then
        error "Invalid plan: $plan. Must be 'design_partner' or 'enterprise'."
        exit 1
    fi

    local now
    now=$(date +%s)
    local exp=$((now + expiry_days * 86400))
    local exp_date
    exp_date=$(date -d "@$exp" '+%Y-%m-%d' 2>/dev/null || date -r "$exp" '+%Y-%m-%d' 2>/dev/null || echo "unknown")

    mkdir -p "$LICENSES_DIR"

    # Build claims JSON
    local features_bits
    if [[ "$plan" == "design_partner" ]]; then
        features_bits=$DESIGN_PARTNER_FEATURES
    else
        features_bits=$ENTERPRISE_FEATURES
    fi

    local claims
    if [[ -n "$custom_limits" ]]; then
        # Custom overrides provided as JSON
        claims=$(python3 -c "
import json, sys

base = {
    'org_id': '$org_id',
    'plan': '$plan',
    'iss': 'clampd.dev',
    'iat': $now,
    'exp': $exp
}

overrides = json.loads('$custom_limits')

# Parse limit overrides
limits = {}
for key in ['max_agents', 'max_requests_per_month', 'audit_retention_days']:
    if key in overrides:
        limits[key] = overrides[key]

if limits:
    base['limits'] = limits

# Parse feature overrides
if 'features' in overrides:
    base['features'] = {'flags': overrides['features']}

print(json.dumps(base))
")
    else
        claims=$(python3 -c "
import json
print(json.dumps({
    'org_id': '$org_id',
    'plan': '$plan',
    'iss': 'clampd.dev',
    'iat': $now,
    'exp': $exp
}))
")
    fi

    # Sign JWT with RS256
    local token
    token=$(python3 -c "
import json, sys

try:
    import jwt
except ImportError:
    print('ERROR: PyJWT not installed. Run: pip install PyJWT', file=sys.stderr)
    sys.exit(1)

with open('$KEYS_DIR/private.pem', 'r') as f:
    private_key = f.read()

claims = json.loads('''$claims''')

token = jwt.encode(claims, private_key, algorithm='RS256')
print(token)
")

    if [[ "$token" == ERROR* ]]; then
        error "$token"
        exit 1
    fi

    # Save license file
    local license_file="$LICENSES_DIR/${org_id}_${plan}.jwt"
    echo "$token" > "$license_file"

    # Save metadata
    cat > "$LICENSES_DIR/${org_id}_${plan}.json" <<METADATA
{
  "org_id": "$org_id",
  "plan": "$plan",
  "issued": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "expires": "$exp_date",
  "expiry_days": $expiry_days,
  "claims": $claims
}
METADATA

    echo ""
    info "License generated for ${CYAN}$org_id${NC} (${YELLOW}$plan${NC})"
    echo ""
    echo -e "  Plan:       ${YELLOW}$plan${NC}"
    echo -e "  Org ID:     ${CYAN}$org_id${NC}"
    echo -e "  Expires:    $exp_date ($expiry_days days)"

    if [[ "$plan" == "design_partner" ]]; then
        echo -e "  Agents:     5"
        echo -e "  Requests:   10,000/month"
        echo -e "  Retention:  7 days"
        echo -e "  Features:   Dashboard, Anomaly Detection"
    else
        echo -e "  Agents:     Unlimited"
        echo -e "  Requests:   Unlimited"
        echo -e "  Retention:  365 days"
        echo -e "  Features:   All"
    fi

    if [[ -n "$custom_limits" ]]; then
        echo -e "  Overrides:  $custom_limits"
    fi

    echo ""
    echo -e "  File:       $license_file"
    echo ""
    echo "──────────────────────────────────────────────────────────────"
    echo "CLAMPD_LICENSE_KEY=$token"
    echo "──────────────────────────────────────────────────────────────"
    echo ""
    info "Add to .env:  CLAMPD_LICENSE_KEY=$token"
}

# ── Decode a license token ───────────────────────────────────────────

cmd_decode() {
    local token="$1"

    python3 -c "
import json, sys, base64

import os
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

token = '$token'
parts = token.split('.')
if len(parts) != 3:
    print('Invalid JWT format', file=sys.stderr)
    sys.exit(1)

# Decode header
header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
header = json.loads(base64.urlsafe_b64decode(header_b64))

# Decode payload
payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))

import datetime

print('Header:')
print(json.dumps(header, indent=2))
print()
print('Claims:')
print(json.dumps(payload, indent=2))
print()

# Human-readable info
plan = payload.get('plan', 'unknown')
org = payload.get('org_id', 'unknown')
exp = payload.get('exp', 0)
iat = payload.get('iat', 0)
exp_date = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
iat_date = datetime.datetime.fromtimestamp(iat, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

now = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
days_left = max(0, (exp - now) / 86400)

print(f'Org:      {org}')
print(f'Plan:     {plan}')
print(f'Issued:   {iat_date}')
print(f'Expires:  {exp_date} ({days_left:.0f} days remaining)')

# Feature flags
features = payload.get('features', {})
if features:
    flags = features.get('flags', 0)
    flag_names = []
    names = ['DASHBOARD','SSO','COMPLIANCE_EXPORT','RBAC','A2A','WEBHOOKS','PII_QUARANTINE','SCOPE_PERMISSIONS','ANOMALY_DETECTION']
    for i, name in enumerate(names):
        if flags & (1 << i):
            flag_names.append(name)
    print(f'Features: {\" | \".join(flag_names) if flag_names else \"(plan defaults)\"}')
else:
    print('Features: (plan defaults)')

# Limits
limits = payload.get('limits', {})
if limits:
    print(f'Limits:   {json.dumps(limits)}')
else:
    print('Limits:   (plan defaults)')

# Signature verification
if HAS_JWT and os.path.exists('$KEYS_DIR/public.pem'):
    try:
        with open('$KEYS_DIR/public.pem', 'r') as f:
            pub_key = f.read()
        jwt.decode(token, pub_key, algorithms=['RS256'], issuer='clampd.dev')
        print()
        print('Signature: VALID')
    except jwt.ExpiredSignatureError:
        print()
        print('Signature: VALID (but EXPIRED)')
    except Exception as e:
        print()
        print(f'Signature: INVALID ({e})')

import os
" 2>&1
}

# ── List issued licenses ─────────────────────────────────────────────

cmd_list() {
    if [[ ! -d "$LICENSES_DIR" ]] || [[ -z "$(ls -A "$LICENSES_DIR"/*.json 2>/dev/null)" ]]; then
        warn "No licenses issued yet."
        return 0
    fi

    echo ""
    printf "%-25s %-18s %-12s %-12s %s\n" "ORG ID" "PLAN" "ISSUED" "EXPIRES" "STATUS"
    printf "%-25s %-18s %-12s %-12s %s\n" "------" "----" "------" "-------" "------"

    for f in "$LICENSES_DIR"/*.json; do
        local org plan issued expires
        org=$(python3 -c "import json; d=json.load(open('$f')); print(d['org_id'])")
        plan=$(python3 -c "import json; d=json.load(open('$f')); print(d['plan'])")
        issued=$(python3 -c "import json; d=json.load(open('$f')); print(d['issued'][:10])")
        expires=$(python3 -c "import json; d=json.load(open('$f')); print(d['expires'])")

        local now_ts exp_ts status
        now_ts=$(date +%s)
        exp_ts=$(python3 -c "import json; d=json.load(open('$f')); print(d['claims']['exp'])")

        if (( now_ts > exp_ts )); then
            status="${RED}EXPIRED${NC}"
        else
            local days_left=$(( (exp_ts - now_ts) / 86400 ))
            if (( days_left < 30 )); then
                status="${YELLOW}${days_left}d left${NC}"
            else
                status="${GREEN}ACTIVE${NC}"
            fi
        fi

        printf "%-25s %-18s %-12s %-12s " "$org" "$plan" "$issued" "$expires"
        echo -e "$status"
    done
    echo ""
}

# ── Obfuscate public key for Rust embedding ──────────────────────────

cmd_obfuscate_key() {
    if [[ ! -f "$KEYS_DIR/public.pem" ]]; then
        error "No public key found. Run './generate-license.sh init' first."
        exit 1
    fi

    local xor_key="${1:-0xAB}"

    info "Generating obfuscated public key for Rust..."
    echo ""

    python3 -c "
xor_key = $xor_key

with open('$KEYS_DIR/public.pem', 'rb') as f:
    data = f.read()

obfuscated = bytes([b ^ xor_key for b in data])

# Output as Rust byte array
print(f'/// XOR key: {hex(xor_key)}')
print(f'/// Original size: {len(data)} bytes')
print(f'pub(crate) const OBFUSCATED_PUB_KEY: [u8; {len(obfuscated)}] = [')

line = '    '
for i, b in enumerate(obfuscated):
    line += f'0x{b:02x},'
    if (i + 1) % 16 == 0:
        print(line)
        line = '    '

if line.strip():
    print(line)

print('];')
print()
print(f'pub(crate) const PUB_KEY_XOR: u8 = {hex(xor_key)};')
"

    echo ""
    info "Copy the output above into services/crates/ag-license/src/key.rs"
}

# ── Main dispatch ────────────────────────────────────────────────────

usage() {
    echo "Clampd License Generator"
    echo ""
    echo "Usage:"
    echo "  $0 init                                 Generate RSA-4096 keypair (one-time)"
    echo "  $0 design_partner <org_id> [days]       Issue Design Partner license"
    echo "  $0 enterprise <org_id> [days]            Issue Enterprise license"
    echo "  $0 custom <org_id> '<json>' [days]       Issue license with custom overrides"
    echo "  $0 decode <token>                        Decode and inspect a license JWT"
    echo "  $0 list                                  List all issued licenses"
    echo "  $0 obfuscate-key [xor_key]               Generate obfuscated key for Rust"
    echo ""
    echo "Examples:"
    echo "  $0 init"
    echo "  $0 design_partner acme-corp"
    echo "  $0 design_partner acme-corp 365"
    echo "  $0 enterprise big-co 730"
    echo "  $0 custom acme-corp '{\"max_agents\":50}'"
    echo "  $0 decode eyJhbGciOiJSUzI1NiJ9..."
    echo ""
    echo "Feature Flags (for custom overrides):"
    echo "  DASHBOARD=1  SSO=2  COMPLIANCE_EXPORT=4  RBAC=8  A2A=16"
    echo "  WEBHOOKS=32  PII_QUARANTINE=64  SCOPE_PERMISSIONS=128  ANOMALY_DETECTION=256"
    echo "  Example: '{\"features\": 511}' = all features"
    echo "  Example: '{\"features\": 257}' = DASHBOARD + ANOMALY_DETECTION (design partner default)"
}

case "${1:-}" in
    init)
        cmd_init
        ;;
    design_partner)
        [[ -z "${2:-}" ]] && { error "Missing org_id. Usage: $0 design_partner <org_id> [days]"; exit 1; }
        generate_license "design_partner" "$2" "${3:-180}"
        ;;
    enterprise)
        [[ -z "${2:-}" ]] && { error "Missing org_id. Usage: $0 enterprise <org_id> [days]"; exit 1; }
        generate_license "enterprise" "$2" "${3:-365}"
        ;;
    custom)
        [[ -z "${2:-}" ]] && { error "Missing org_id."; exit 1; }
        [[ -z "${3:-}" ]] && { error "Missing JSON overrides."; exit 1; }
        generate_license "${4:-design_partner}" "$2" "${5:-180}" "$3"
        ;;
    decode)
        [[ -z "${2:-}" ]] && { error "Missing token."; exit 1; }
        cmd_decode "$2"
        ;;
    list)
        cmd_list
        ;;
    obfuscate-key)
        cmd_obfuscate_key "${2:-171}"
        ;;
    *)
        usage
        ;;
esac
