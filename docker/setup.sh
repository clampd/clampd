#!/bin/sh
# Clampd Quick Setup — generates .env with all required secrets.
# Usage: curl -fsSL https://clampd.dev/setup.sh | sh
#   or:  ./setup.sh
set -e

ENV_FILE="${1:-.env}"

if [ -f "$ENV_FILE" ] && [ "${CLAMPD_FORCE_SETUP:-}" != "1" ]; then
  echo "  $ENV_FILE already exists. Set CLAMPD_FORCE_SETUP=1 to overwrite."
  exit 1
fi

# Require openssl
if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is required. Install it and try again."
  exit 1
fi

gen_hex() { openssl rand -hex "$1"; }

JWT_SECRET=$(gen_hex 32)
POSTGRES_PASSWORD=$(gen_hex 16)
REDIS_PASSWORD=$(gen_hex 16)
AG_INTERNAL_SECRET=$(gen_hex 64)
NATS_TOKEN=$(gen_hex 32)
AG_TOKEN_ENCRYPTION_KEY=$(gen_hex 32)

cat > "$ENV_FILE" <<EOF
# Clampd v0.9.0 — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Docs: https://clampd.dev/docs

# ── License (required) ────────────────────────────────────────
# Sign up at https://app.clampd.dev to get your license key.
CLAMPD_LICENSE_KEY=

# ── Security (auto-generated) ────────────────────────────────
JWT_SECRET=${JWT_SECRET}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
AG_INTERNAL_SECRET=${AG_INTERNAL_SECRET}
NATS_TOKEN=${NATS_TOKEN}
AG_TOKEN_ENCRYPTION_KEY=${AG_TOKEN_ENCRYPTION_KEY}

# ── Database (default: local containers via --profile local-infra) ─
# For managed databases (Neon, Supabase, Upstash), uncomment and set:
# DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require
# REDIS_URL=redis://:password@host:6379

# ── Optional ─────────────────────────────────────────────────
# CLICKHOUSE_URL=http://clickhouse:8123
# CLAMPD_SAAS_URL=
# CLAMPD_ENV=production
EOF

echo ""
echo "  .env created with fresh secrets."
echo ""
echo "  Next steps:"
echo "    1. Add your license key:  Edit $ENV_FILE and set CLAMPD_LICENSE_KEY"
echo "       (get one at https://app.clampd.dev)"
echo ""
echo "    2. Start the pipeline:"
echo "       docker compose -f docker-compose.proxy.yml --profile local-infra up -d"
echo ""
echo "    3. Install an SDK:"
echo "       pip install clampd        # Python"
echo "       npm install @clampd/sdk   # TypeScript"
echo ""
