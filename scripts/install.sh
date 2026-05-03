#!/bin/bash
# singbox2proxy installer for Linux / macOS
# Supports two modes:
#   standalone (default) — downloads pre-built binary, no Python needed
#   python               — installs via pip/pipx, requires Python 3.9+
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nichind/singbox2proxy/main/scripts/install.sh | sh
#   curl -fsSL ... | sh -s -- --python
#   curl -fsSL ... | sh -s -- --standalone
#   curl -fsSL ... | sh -s -- --help
set -e

REPO="nichind/singbox2proxy"
BIN_NAME="sb2p"
BIN_ALIAS="singbox2proxy"
MODE="standalone"
INSTALL_DIR="${SB2P_INSTALL_DIR:-$HOME/.local/bin}"

# --- Parse arguments ---
for arg in "$@"; do
    case "$arg" in
        --python|--pip) MODE="python" ;;
        --standalone|--binary) MODE="standalone" ;;
        --help|-h)
            echo "singbox2proxy installer"
            echo ""
            echo "Usage: curl -fsSL <url> | sh -s -- [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --standalone   Download pre-built binary (default, no Python needed)"
            echo "  --python       Install via pip/pipx (requires Python 3.9+)"
            echo "  --help         Show this help"
            echo ""
            echo "Environment:"
            echo "  SB2P_INSTALL_DIR   Custom install directory (default: ~/.local/bin)"
            exit 0
            ;;
    esac
done

echo "==> singbox2proxy installer (mode: $MODE)"

# --- Ensure install directory exists and is in PATH ---
ensure_path() {
    mkdir -p "$INSTALL_DIR"
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            export PATH="$INSTALL_DIR:$PATH"
            # Add to shell profile
            for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
                if [ -f "$rc" ]; then
                    if ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
                        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$rc"
                    fi
                fi
            done
            ;;
    esac
}

# --- Create alias symlink/copy ---
create_aliases() {
    local src="$1"
    local dir
    dir="$(dirname "$src")"

    # Create the second alias
    if [ "$(basename "$src")" = "$BIN_NAME" ]; then
        ln -sf "$src" "$dir/$BIN_ALIAS" 2>/dev/null || cp -f "$src" "$dir/$BIN_ALIAS"
    else
        ln -sf "$src" "$dir/$BIN_NAME" 2>/dev/null || cp -f "$src" "$dir/$BIN_NAME"
    fi
}

# ===========================================================
# STANDALONE MODE
# ===========================================================
install_standalone() {
    echo "==> Detecting platform..."

    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7*) ARCH="armv7" ;;
        i?86) ARCH="386" ;;
        *) echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    case "$OS" in
        linux) PLATFORM="linux" ;;
        darwin) PLATFORM="macos" ;;
        *) echo "ERROR: Unsupported OS: $OS (use --python mode or Windows installer)"; exit 1 ;;
    esac

    echo "==> Platform: ${PLATFORM}-${ARCH}"

    # Get latest release tag
    echo "==> Fetching latest release..."
    RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: singbox2proxy-installer")

    TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    if [ -z "$TAG" ]; then
        echo "ERROR: Could not determine latest release. Falling back to Python mode..."
        install_python
        return
    fi

    VERSION="${TAG#v}"
    ASSET_NAME="sb2p-${PLATFORM}-${ARCH}"
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/$ASSET_NAME"

    echo "==> Downloading $ASSET_NAME ($TAG)..."
    TMP_DIR=$(mktemp -d)
    TMP_FILE="$TMP_DIR/$BIN_NAME"

    if ! curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL" 2>/dev/null; then
        echo "==> Binary not available for ${PLATFORM}-${ARCH}. Falling back to Python mode..."
        rm -rf "$TMP_DIR"
        install_python
        return
    fi

    if [ ! -s "$TMP_FILE" ]; then
        echo "==> Download produced empty file. Falling back to Python mode..."
        rm -rf "$TMP_DIR"
        install_python
        return
    fi

    chmod +x "$TMP_FILE"

    ensure_path

    mv -f "$TMP_FILE" "$INSTALL_DIR/$BIN_NAME"
    create_aliases "$INSTALL_DIR/$BIN_NAME"

    rm -rf "$TMP_DIR"
    echo "==> Installed to $INSTALL_DIR/$BIN_NAME"
}

# ===========================================================
# PYTHON MODE
# ===========================================================
install_python() {
    # Detect Python
    PYTHON=""
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
            if [ -n "$ver" ]; then
                major=$(echo "$ver" | cut -d. -f1)
                minor=$(echo "$ver" | cut -d. -f2)
                if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
                    PYTHON="$cmd"
                    break
                fi
            fi
        fi
    done

    # Install Python if missing
    if [ -z "$PYTHON" ]; then
        echo "==> Python 3.9+ not found, installing..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-pip python3-venv
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y python3 python3-pip
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -Sy --noconfirm python python-pip
        elif command -v apk >/dev/null 2>&1; then
            sudo apk add python3 py3-pip
        elif command -v brew >/dev/null 2>&1; then
            brew install python3
        elif command -v pkg >/dev/null 2>&1; then
            pkg install -y python3
        else
            echo "ERROR: Cannot install Python automatically. Install Python 3.9+ manually."
            exit 1
        fi

        for cmd in python3 python; do
            if command -v "$cmd" >/dev/null 2>&1; then
                PYTHON="$cmd"
                break
            fi
        done

        if [ -z "$PYTHON" ]; then
            echo "ERROR: Python installation failed."
            exit 1
        fi
    fi

    echo "==> Using $PYTHON ($($PYTHON --version 2>&1))"

    # Install package
    if command -v pipx >/dev/null 2>&1; then
        echo "==> Installing via pipx..."
        pipx install singbox2proxy --force
    elif $PYTHON -m pipx --version >/dev/null 2>&1; then
        echo "==> Installing via python -m pipx..."
        $PYTHON -m pipx install singbox2proxy --force
    else
        echo "==> Installing via pip..."
        $PYTHON -m pip install --user singbox2proxy 2>/dev/null || $PYTHON -m pip install singbox2proxy
    fi

    # Ensure aliases exist
    ensure_path

    # pip creates sb2p and singbox2proxy entry points, but verify
    if ! command -v "$BIN_NAME" >/dev/null 2>&1; then
        # Create wrapper script
        SCRIPT_PATH="$INSTALL_DIR/$BIN_NAME"
        cat > "$SCRIPT_PATH" << EOF
#!/bin/sh
exec $PYTHON -m singbox2proxy "\$@"
EOF
        chmod +x "$SCRIPT_PATH"
        create_aliases "$SCRIPT_PATH"
    fi
}

# ===========================================================
# Run
# ===========================================================
if [ "$MODE" = "standalone" ]; then
    install_standalone
else
    install_python
fi

# --- Verify ---
echo ""
if command -v "$BIN_NAME" >/dev/null 2>&1; then
    echo "==> Done! singbox2proxy installed successfully."
    echo "    Version: $($BIN_NAME --version 2>/dev/null || echo 'unknown')"
    echo "    Usage:   sb2p \"vless://...\""
    echo "             singbox2proxy \"vless://...\""
else
    echo "==> Installation complete. Restart your shell or run:"
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    echo "    Then: sb2p \"vless://...\""
fi
echo ""
