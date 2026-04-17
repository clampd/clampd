#!/bin/sh
# Clampd CLI installer - downloads prebuilt binary from GitHub Releases.
# Usage: curl -fsSL https://clampd.dev/install.sh | sh
set -e

REPO="clampd/clampd"
VERSION="${CLAMPD_VERSION:-latest}"
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
  ARTIFACT="clampd-${os}-${arch}.zip"
else
  ARTIFACT="clampd-${os}-${arch}.tar.gz"
fi

# Resolve version
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')
  if [ -z "$VERSION" ]; then
    echo "Failed to detect latest version. Set CLAMPD_VERSION=v0.9.0 manually."
    exit 1
  fi
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}"

echo "Installing clampd ${VERSION} (${os}/${arch})..."
echo "  From: ${URL}"
echo "  To:   ${INSTALL_DIR}/clampd"

# Download and extract
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "$os" = "windows" ]; then
  curl -fsSL "$URL" -o "$TMP/clampd.zip"
  unzip -q "$TMP/clampd.zip" -d "$TMP"
else
  curl -fsSL "$URL" | tar -xzf - -C "$TMP"
fi

# Install
BINARY=$(find "$TMP" -name "clampd*" -type f ! -name "*.tar.gz" ! -name "*.zip" | head -1)
if [ -z "$BINARY" ]; then
  echo "Error: binary not found in archive"
  exit 1
fi

chmod +x "$BINARY"

if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY" "$INSTALL_DIR/clampd"
else
  sudo mv "$BINARY" "$INSTALL_DIR/clampd"
fi

echo ""
echo "clampd installed successfully!"
echo ""
clampd --version 2>/dev/null || echo "Run: clampd --help"
