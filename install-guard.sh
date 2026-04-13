#!/bin/sh
# clampd-guard installer — runtime security for Claude Code and Cursor.
# Usage: curl -fsSL https://clampd.dev/install-guard.sh | sh
set -e

REPO="clampd/clampd"
VERSION="${CLAMPD_GUARD_VERSION:-latest}"
INSTALL_DIR="${CLAMPD_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  os="linux" ;;
  Darwin) os="darwin" ;;
  MINGW*|MSYS*|CYGWIN*) os="windows" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)  arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Build artifact name
if [ "$os" = "windows" ]; then
  ARTIFACT="clampd-guard-${os}-${arch}.zip"
else
  ARTIFACT="clampd-guard-${os}-${arch}.tar.gz"
fi

# Resolve version
if [ "$VERSION" = "latest" ]; then
  # Guard releases use guard-v* tags
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep '"tag_name"' | grep 'guard-v' | head -1 \
    | sed 's/.*"tag_name": *"//;s/".*//')
  if [ -z "$VERSION" ]; then
    echo "Failed to detect latest version. Set CLAMPD_GUARD_VERSION=guard-v0.1.0 manually."
    exit 1
  fi
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}"

echo "Installing clampd-guard ${VERSION} (${os}/${arch})..."
echo "  From: ${URL}"
echo "  To:   ${INSTALL_DIR}/clampd-guard"

# Download and extract
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "$os" = "windows" ]; then
  curl -fsSL "$URL" -o "$TMP/clampd-guard.zip"
  unzip -q "$TMP/clampd-guard.zip" -d "$TMP"
else
  curl -fsSL "$URL" | tar -xzf - -C "$TMP"
fi

# Install
BINARY=$(find "$TMP" -name "clampd-guard*" -type f ! -name "*.tar.gz" ! -name "*.zip" | head -1)
if [ -z "$BINARY" ]; then
  echo "Error: binary not found in archive"
  exit 1
fi

chmod +x "$BINARY"

if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY" "$INSTALL_DIR/clampd-guard"
else
  sudo mv "$BINARY" "$INSTALL_DIR/clampd-guard"
fi

echo ""
echo "clampd-guard installed successfully!"
echo ""
echo "Quick start:"
echo "  clampd-guard setup \\"
echo "    --url https://your-gateway:8080 \\"
echo "    --key your-api-key \\"
echo "    --agent your-agent-id \\"
echo "    --secret your-agent-secret"
echo ""
echo "Every Claude Code and Cursor tool call will be verified before execution."
echo ""
