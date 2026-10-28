#!/usr/bin/env bash
# ChainShield installer for Linux and Termux
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"

echo "ChainShield installer"
echo "Python: $($PYTHON --version 2>&1)"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 is required."
  exit 1
fi

# Check minimum version (3.10+)
"$PYTHON" - <<'PY' || exit 1
import sys
if sys.version_info < (3, 10):
    print("Python 3.10 or newer is required.", file=sys.stderr)
    raise SystemExit(1)
print(f"Python version OK: {sys.version.split()[0]}")
PY

PIP_OK=0
if "$PYTHON" -m pip --version >/dev/null 2>&1; then
  echo "Installing package (editable)..."
  if "$PYTHON" -m pip install -e "$ROOT" --user 2>/dev/null || "$PYTHON" -m pip install -e "$ROOT"; then
    PIP_OK=1
  else
    echo "Warning: pip install failed; falling back to PYTHONPATH launcher only."
  fi
else
  echo "pip not found; using PYTHONPATH launcher only."
fi

# Config directory
if [ -n "${TERMUX_VERSION:-}" ] || [ -n "${PREFIX:-}" ]; then
  CONF_DIR="${HOME}/.config/chainshield"
else
  CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/chainshield"
fi
mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR" 2>/dev/null || true
if [ ! -f "$CONF_DIR/config.toml" ]; then
  cp "$ROOT/config.example.toml" "$CONF_DIR/config.toml"
  chmod 600 "$CONF_DIR/config.toml" 2>/dev/null || true
  echo "Wrote example config: $CONF_DIR/config.toml"
else
  echo "Config already exists: $CONF_DIR/config.toml"
fi

# Always install a launcher that works even without pip
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/chainshield" << EOFW
#!/usr/bin/env bash
export PYTHONPATH="${ROOT}:\${PYTHONPATH:-}"
exec ${PYTHON} -m chainshield "\$@"
EOFW
chmod +x "$BIN_DIR/chainshield"
echo "Installed launcher: $BIN_DIR/chainshield"
echo "Ensure $BIN_DIR is on your PATH."
if [ "$PIP_OK" = "1" ]; then
  echo "Package install: OK (editable)"
else
  echo "Package install: launcher-only (PYTHONPATH)"
fi
echo "Done. Run: chainshield --version"
