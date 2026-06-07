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

# Run PEzor
"$PEZOR_DIR/PEzor.sh" "${FLAGS[@]}" "$INPUT" || exit 1

# PEzor creates {input}.packed.exe next to the input
PACKED="${INPUT}.packed.exe"
if [ -f "$PACKED" ]; then
    mv "$PACKED" "$OUTPUT"
    echo "[pezor_wrap] Success: moved $PACKED -> $OUTPUT"
else
    echo "[pezor_wrap] ERROR: Expected output not found: $PACKED"
    ls -la "$(dirname "$INPUT")"/*.packed.* 2>/dev/null
    exit 1
fi
