#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runtime="$repo/empirical_results/qemu_runtime"
source="$runtime/qemu-src"
build="$runtime/qemu-build"
revision=eca2c16212ef9dcb0871de39bb9d1c2efebe76be

mkdir -p "$runtime"
if [ ! -d "$source/.git" ]; then
    git clone --filter=blob:limit=5m https://gitlab.com/qemu-project/qemu.git "$source"
fi
git -C "$source" fetch --depth 1 origin "$revision"
if [ "$(git -C "$source" rev-parse HEAD)" != "$revision" ]; then
    echo "QEMU source exists at a different revision; refusing to overwrite it" >&2
    exit 1
fi
if patch --dry-run -s -p1 -d "$source" \
    < "$repo/ops/qemu/qemu-ram-identity.patch"; then
    patch -s -p1 -d "$source" < "$repo/ops/qemu/qemu-ram-identity.patch"
elif ! patch --dry-run -R -s -p1 -d "$source" \
    < "$repo/ops/qemu/qemu-ram-identity.patch"; then
    echo "QEMU RAM identity patch is neither applicable nor already applied" >&2
    exit 1
fi

mkdir -p "$build"
if [ ! -f "$build/build.ninja" ]; then
    cd "$build"
    "$source/configure" \
        --target-list=x86_64-softmmu \
        --enable-plugins \
        --disable-docs \
        --disable-gtk \
        --disable-sdl \
        --disable-opengl \
        --disable-spice \
        --disable-vnc \
        --disable-slirp \
        --disable-curl \
        --disable-gnutls \
        --disable-libssh \
        --disable-rdma \
        --disable-cap-ng \
        --disable-werror
fi
ninja -C "$build" -j"${QEMU_BUILD_JOBS:-2}" qemu-system-x86_64
