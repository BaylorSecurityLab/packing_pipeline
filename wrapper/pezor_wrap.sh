#!/bin/bash
# PEzor wrapper for packer_runner
# Usage: pezor_wrap.sh <flags...> <input> <output>
# Runs PEzor inside WSL and moves the output to the specified location.

PEZOR_DIR="/mnt/c/Users/bkoro/projects/PEzor"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/home/banny/go/bin:$PEZOR_DIR:$PEZOR_DIR/deps/donut:$PEZOR_DIR/deps/wclang/_prefix_PEzor_/bin"
export HOME="/home/banny"
export GOPATH="/home/banny/go"

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
    # Try to find any .packed file nearby
    ls -la "$(dirname "$INPUT")"/*.packed.* 2>/dev/null
    exit 1
fi
