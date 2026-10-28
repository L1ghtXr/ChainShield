#!/usr/bin/env bash
set -euo pipefail

echo "ChainShield uninstall"
BIN="${HOME}/.local/bin/chainshield"
if [ -f "$BIN" ]; then
  rm -f "$BIN"
  echo "Removed $BIN"
fi

if command -v pip3 >/dev/null 2>&1; then
  pip3 uninstall -y chainshield 2>/dev/null || true
fi

echo "Config left in place (remove manually if desired):"
echo "  ~/.config/chainshield/"
echo "Done."
