#!/bin/sh
# Installs the NetScope extcap binary into Wireshark's personal extcap folder.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${1:-"$ROOT/build/netscope-extcap"}

if [ ! -x "$BIN" ]; then
    echo "extcap binary not found: $BIN" >&2
    echo "build it first: cmake --build build -j" >&2
    exit 1
fi

TARGET_DIR=""
if command -v tshark >/dev/null 2>&1; then
    TARGET_DIR=$(tshark -G folders 2>/dev/null |
        awk -F'\t' '/Personal Extcap path/ {print $2; exit}')
fi
if [ -z "$TARGET_DIR" ]; then
    TARGET_DIR="$HOME/.local/lib/wireshark/extcap"
fi

mkdir -p "$TARGET_DIR"
ln -sf "$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" "$TARGET_DIR/netscope"
echo "installed: $TARGET_DIR/netscope"
echo "restart Wireshark and open Capture > Options to see the NetScope interfaces"
