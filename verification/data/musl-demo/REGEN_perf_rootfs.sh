#!/bin/sh
# Build an Alpine/musl rootfs containing the unmodified upstream Linux perf CLI.
#
# Output: target/narf-vblk.img (the virtio-blk image used by xtask).
# Requires: root (for chroot), curl, tar, and mke2fs.
set -eu

ALPINE_VER=3.21
ALPINE_REL=3.21.0
ARCH=x86_64
URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}/releases/${ARCH}/alpine-minirootfs-${ALPINE_REL}-${ARCH}.tar.gz"

if [ "$(id -u)" -ne 0 ]; then
    echo "REGEN_perf_rootfs.sh requires root so Alpine apk can run in chroot" >&2
    exit 1
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-vblk.img"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

curl -fsSL -o "$WORK/mini.tar.gz" "$URL"
mkdir -p "$WORK/root"
tar xzf "$WORK/mini.tar.gz" -C "$WORK/root"
cp /etc/resolv.conf "$WORK/root/etc/resolv.conf"

# The package is Alpine's unmodified linux-tools perf build. Installing it in
# the staging tree also captures the exact musl shared-library closure.
chroot "$WORK/root" /sbin/apk add --no-cache perf

mkdir -p "$ROOT/target"
rm -f "$OUT"
mke2fs -q -F -t ext2 -b 1024 \
  -O ^has_journal,^extent,^64bit,^metadata_csum,^dir_index,^resize_inode,^huge_file,^flex_bg,^ext_attr \
  -d "$WORK/root" "$OUT" 131072

echo "built $OUT with Alpine perf ($(du -h "$OUT" | cut -f1))"
echo "test it: verification/data/musl-demo/TEST_perf_cli.sh"
