#!/bin/bash
# PEzor wrapper for packer_runner
# Usage: pezor_wrap.sh <flags...> <input> <output>
# Runs PEzor inside WSL (Ubuntu-26.04) and moves the output to the specified location.

PEZOR_DIR="/opt/PEzor"
export PATH="/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin:$PEZOR_DIR:$PEZOR_DIR/deps/donut:$PEZOR_DIR/deps/wclang/_prefix_PEzor_/bin"
export HOME="/root"
export GOPATH="/root/go"

# Parse: last two args are input and output, everything else is PEzor flags
ARGS=("$@")
NUM_ARGS=${#ARGS[@]}
OUTPUT="${ARGS[$NUM_ARGS-1]}"
INPUT="${ARGS[$NUM_ARGS-2]}"
FLAGS=("${ARGS[@]:0:$NUM_ARGS-2}")

echo "[pezor_wrap] Input:  $INPUT"
echo "[pezor_wrap] Output: $OUTPUT"
echo "[pezor_wrap] Flags:  ${FLAGS[*]}"

# PEzor.sh does not quote $BLOB internally, so any space in the filename
# causes it to fail. Symlink the input to a temp path with no spaces.
TMP_DIR=$(mktemp -d)
EXT="${INPUT##*.}"
SAFE_INPUT="$TMP_DIR/input.$EXT"
ln -s "$INPUT" "$SAFE_INPUT" 2>/dev/null || cp "$INPUT" "$SAFE_INPUT"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# Run PEzor against the space-free temp path
"$PEZOR_DIR/PEzor.sh" "${FLAGS[@]}" "$SAFE_INPUT" || exit 1

# PEzor creates {input}.packed.exe next to the input
PACKED="${SAFE_INPUT}.packed.exe"
if [ -f "$PACKED" ]; then
    mv "$PACKED" "$OUTPUT"
    echo "[pezor_wrap] Success: moved $PACKED -> $OUTPUT"
else
    echo "[pezor_wrap] ERROR: Expected output not found: $PACKED"
    ls -la "$TMP_DIR"/*.packed.* 2>/dev/null
    exit 1
fi
