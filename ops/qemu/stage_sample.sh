#!/bin/sh
# Stage a real packed sample into a COPY of the pristine Windows base image and
# switch the PandaPilot service to run it live (not the certification fixture).
# Never mutates the base.  Run as root (qemu-nbd + mount + offline hive edit).
#
#   sudo ops/qemu/stage_sample.sh <sample.exe> <out_image.qcow2> [timeout_seconds]
#
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
runtime="$repo/empirical_results/qemu_runtime"
base="$runtime/windows10-qemu-repair.qcow2"
launcher="$repo/ops/panda/build/guest_launcher.exe"
sample="${1:?usage: stage_sample.sh <sample.exe> <out_image.qcow2> [timeout]}"
out="${2:?usage: stage_sample.sh <sample.exe> <out_image.qcow2> [timeout]}"
timeout="${3:-300}"
nbd=/dev/nbd0
mnt=$(mktemp -d)

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for f in "$base" "$launcher" "$sample"; do
    [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

cleanup() {
    mountpoint -q "$mnt" && umount "$mnt" || true
    qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
    rmdir "$mnt" 2>/dev/null || true
}
trap cleanup EXIT

echo "== base integrity =="
qemu-img check "$base"
echo "== make working copy (base stays pristine) =="
cp --reflink=auto "$base" "$out"

echo "== connect $out via $nbd =="
qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
qemu-nbd --connect="$nbd" "$out"
sleep 1; partprobe "$nbd" 2>/dev/null || true; sleep 1

target=""
for part in "$nbd"p1 "$nbd"p2 "$nbd"p3 "$nbd"p4 "$nbd"; do
    [ -b "$part" ] || continue
    umount "$mnt" 2>/dev/null || true
    if mount -t ntfs-3g -o ro "$part" "$mnt" 2>/dev/null; then
        if [ -d "$mnt/Panda" ] && [ -f "$mnt/Windows/System32/config/SYSTEM" ]; then
            target="$part"; umount "$mnt"; break
        fi
        umount "$mnt"
    fi
done
[ -n "$target" ] || { echo "could not locate Windows/Panda partition" >&2; exit 1; }
echo "Windows partition: $target"

echo "== refuse hibernated/dirty NTFS =="
mount -t ntfs-3g -o rw "$target" "$mnt"

echo "== stage sample.exe + launcher; clear fixture-only flags =="
cp -f "$launcher" "$mnt/Panda/guest_launcher.exe"
cp -f "$sample"   "$mnt/Panda/sample.exe"
rm -f "$mnt/Panda/single_process.txt"   # live mode: sample runs to exit/idle
rm -f "$mnt/Panda/idle_ms.txt"          # live default idle (launcher clamps 120s)
sync

echo "== switch PandaPilot ImagePath to sample mode (offline hive) =="
python3 "$repo/ops/qemu/set_pilot_imagepath.py" \
    "$mnt/Windows/System32/config/SYSTEM" \
    --image 'C:\Panda\sample.exe' --timeout "$timeout"

echo "== verify sample SHA-256 in image =="
want=$(sha256sum "$sample" | awk '{print $1}')
got=$(sha256sum "$mnt/Panda/sample.exe" | awk '{print $1}')
echo "sample want=$want"; echo "sample got =$got"
[ "$want" = "$got" ] || { echo "sample hash MISMATCH" >&2; exit 1; }

umount "$mnt"
qemu-nbd --disconnect "$nbd"
trap - EXIT
rmdir "$mnt" 2>/dev/null || true

echo "== final integrity =="
qemu-img check "$out"
echo "OK: staged sample into $out (timeout ${timeout}s, live mode)"
