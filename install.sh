#!/bin/sh
# Clampd CLI installer — https://clampd.dev
# Usage: curl -fsSL https://clampd.dev/install | sh
set -e

REPO="clampd/clampd"
INSTALL_DIR="/usr/local/bin"
BINARY="clampd"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux) ;;
  darwin)
    echo "macOS detected — clampd runs inside Docker."
    echo "Use: docker run --rm -it ghcr.io/$REPO/clampd-cli:latest --help"
    exit 0
    ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest release tag
echo "Fetching latest release..."
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$TAG" ]; then
  echo "Could not determine latest release. Using Docker instead:"
  echo "  docker run --rm -it ghcr.io/$REPO/clampd-cli:latest --help"
  exit 1
fi

URL="https://github.com/$REPO/releases/download/$TAG/clampd-linux-$ARCH"
echo "Downloading clampd $TAG for linux/$ARCH..."

TMP=$(mktemp)
curl -fsSL "$URL" -o "$TMP"
chmod +x "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP" "$INSTALL_DIR/$BINARY"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "$TMP" "$INSTALL_DIR/$BINARY"
fi

echo ""
echo "clampd installed to $INSTALL_DIR/$BINARY"
echo ""
echo "Quick start:"
echo "  1. Generate a license key:"
echo "       ./generate-license.sh design_partner <org-id>"
echo "  2. Set it in your .env file:"
echo "       echo 'CLAMPD_LICENSE_KEY=<your-key>' >> .env"
echo "  3. Activate and verify:"
echo "       clampd activate --license <YOUR_LICENSE_TOKEN>"
echo "       clampd cluster status"
echo "       clampd agent list"
echo ""
echo "NOTE: A valid CLAMPD_LICENSE_KEY is required for all services to start."
echo "Docs: https://clampd.dev/docs"
