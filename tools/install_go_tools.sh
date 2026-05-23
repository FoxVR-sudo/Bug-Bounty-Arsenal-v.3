#!/usr/bin/env bash
set -euo pipefail

# Installs Go (user-space, no sudo) and then installs:
# - subfinder
# - amass
#
# Output binaries:
# - ~/.local/go/bin/go
# - ~/go/bin/subfinder
# - ~/go/bin/amass

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_RAW=$(uname -m)

case "$ARCH_RAW" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)
    echo "Unsupported arch: $ARCH_RAW" >&2
    exit 1
    ;;
esac

if [[ "$OS" != "linux" && "$OS" != "darwin" ]]; then
  echo "Unsupported OS: $OS" >&2
  exit 1
fi

GO_VER=${GO_VER:-""}
if [[ -z "$GO_VER" ]]; then
  GO_VER=$(curl -fsSL https://go.dev/VERSION?m=text | head -n 1)
fi

TARBALL="${GO_VER}.${OS}-${ARCH}.tar.gz"
URL="https://go.dev/dl/${TARBALL}"

INSTALL_DIR="$HOME/.local"
GO_DIR="$INSTALL_DIR/go"

mkdir -p "$INSTALL_DIR"
rm -rf "$GO_DIR"

echo "Downloading: $URL"
curl -fL "$URL" -o "/tmp/${TARBALL}"

echo "Extracting to: $GO_DIR"
tar -C "$INSTALL_DIR" -xzf "/tmp/${TARBALL}"

export PATH="$GO_DIR/bin:$HOME/go/bin:$PATH"

echo "Go OK: $(go version)"

# Some shared hosts (cPanel/CloudLinux) can throw EAGAIN when the Go
# compiler tries to fan out too many compile/asm processes or OS threads.
# Default to a conservative, serial build unless the caller overrides.
GO_BUILD_PARALLELISM=${GO_BUILD_PARALLELISM:-1}
if [[ -z "${GOMAXPROCS:-}" ]]; then
  export GOMAXPROCS="$GO_BUILD_PARALLELISM"
fi
if [[ -z "${GOFLAGS:-}" ]]; then
  export GOFLAGS="-p=${GO_BUILD_PARALLELISM}"
fi

echo "Installing all Bug Bounty Arsenal Go tools into ~/go/bin ..."

# --- Recon / Asset Discovery ---
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/cmd/amass@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# --- Crawling ---
go install github.com/projectdiscovery/katana/cmd/katana@latest

# --- Fuzzing ---
go install github.com/ffuf/ffuf/v2@latest

# --- Grep / Pattern Matching ---
go install github.com/tomnomnom/gf@latest

# --- XSS ---
go install github.com/hahwul/dalfox/v2@latest

# --- Vulnerability Scanning ---
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "Installed:"
ls -la "$HOME/go/bin" | grep -E 'subfinder|amass|httpx|katana|ffuf|gf|dalfox|nuclei' || true

# Install popular gf pattern sets
GF_DIR="$HOME/.gf"
if [[ ! -d "$GF_DIR" ]]; then
  echo "Cloning gf patterns into $GF_DIR ..."
  git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$GF_DIR" 2>/dev/null || \
    echo "Warning: could not clone gf patterns (git may not be available)"
fi

# Update Nuclei templates
nuclei -update-templates 2>/dev/null || echo "Warning: nuclei template update skipped"

echo
echo "Add to PATH (recommended):"
echo "  export PATH=\"$HOME/.local/go/bin:$HOME/go/bin:\$PATH\""
echo
echo "Optional .env overrides (recommended for Celery/Docker):"
echo "  SUBFINDER_BIN=$HOME/go/bin/subfinder"
echo "  AMASS_BIN=$HOME/go/bin/amass"
echo "  HTTPX_BIN=$HOME/go/bin/httpx"
echo "  KATANA_BIN=$HOME/go/bin/katana"
echo "  FFUF_BIN=$HOME/go/bin/ffuf"
echo "  GF_BIN=$HOME/go/bin/gf"
echo "  DALFOX_BIN=$HOME/go/bin/dalfox"
echo "  NUCLEI_BIN=$HOME/go/bin/nuclei"
