#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$repo/ops/qemu/build"
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Werror \
    -Wl,--no-insert-timestamp \
    "$repo/ops/qemu/validation_fixture.c" \
    -o "$repo/ops/qemu/build/validation_fixture.exe"
