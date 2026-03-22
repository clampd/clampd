#!/usr/bin/env bash
# Generate self-signed TLS certificate for Clampd gateway.
#
# Usage:
#   ./generate-tls.sh                    # generates for localhost
#   ./generate-tls.sh gateway.acme.com   # generates for custom domain
#
# Output:
#   .tls/clampd-gateway.pem   (certificate)
#   .tls/clampd-gateway-key.pem (private key)
#
# Then set in .env:
#   CLAMPD_TLS_CERT=.tls/clampd-gateway.pem
#   CLAMPD_TLS_KEY=.tls/clampd-gateway-key.pem
#   CLAMPD_ENV=production

set -euo pipefail

DOMAIN="${1:-localhost}"
DIR=".tls"
CERT="$DIR/clampd-gateway.pem"
KEY="$DIR/clampd-gateway-key.pem"
DAYS=365

mkdir -p "$DIR"

echo "Generating self-signed TLS certificate for: $DOMAIN"
echo "Valid for: $DAYS days"
echo ""

openssl req -x509 -newkey rsa:4096 \
  -keyout "$KEY" \
  -out "$CERT" \
  -sha256 \
  -days "$DAYS" \
  -nodes \
  -subj "/CN=$DOMAIN/O=Clampd/OU=AgentGuard" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$KEY"
chmod 644 "$CERT"

echo ""
echo "Certificate generated:"
echo "  Cert: $CERT"
echo "  Key:  $KEY"
echo ""
echo "Add to .env:"
echo "  CLAMPD_TLS_CERT=$CERT"
echo "  CLAMPD_TLS_KEY=$KEY"
echo "  CLAMPD_ENV=production"
echo ""
echo "For Docker, mount into the container:"
echo "  volumes:"
echo "    - ./.tls:/tls:ro"
echo "  environment:"
echo "    CLAMPD_TLS_CERT: /tls/clampd-gateway.pem"
echo "    CLAMPD_TLS_KEY: /tls/clampd-gateway-key.pem"
echo ""
echo "NOTE: Self-signed certs are for development/testing only."
echo "For production, use Let's Encrypt (via Caddy) or your CA."
