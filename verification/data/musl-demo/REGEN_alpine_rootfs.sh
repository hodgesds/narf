#!/bin/sh
# Build the Alpine Linux rootfs disk image that /bin/distro_init boots.
#
# NARF mounts this ext2 image (on the QEMU virtio-blk device) at /mnt; the
# /bin/distro_init launcher then chroot()s into it and execs Alpine's OWN
# busybox — a real, unmodified Linux distro userland running on the NARF
# kernel (the container-runtime model). Alpine is the musl-based distro, which
# matches NARF's musl ABI support.
#
# The image is ~28 MiB and is NOT committed to git; build it locally before
# running the distro_init test:
#
#   sh verification/data/musl-demo/REGEN_alpine_rootfs.sh
#   cargo xtask run-interactive --cmd distro_init --expect alpine-shell-ran
#
# Output: target/narf-vblk.img (the path xtask's virtio_blk_image_path() uses
# verbatim when it already exists — it only builds the placeholder otherwise).
#
# Requires: curl, tar, mke2fs (e2fsprogs >= 1.43 for `-d`), unprivileged.
set -e

ALPINE_VER=3.21
ALPINE_REL=3.21.0
ARCH=x86_64
URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}/releases/${ARCH}/alpine-minirootfs-${ALPINE_REL}-${ARCH}.tar.gz"

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-vblk.img"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "fetching $URL"
curl -fsSL -o "$WORK/mini.tar.gz" "$URL"
mkdir -p "$WORK/root"
tar xzf "$WORK/mini.tar.gz" -C "$WORK/root"

mkdir -p "$ROOT/target"
rm -f "$OUT"
# Plain ext2 (no journal/extents/64bit/csum) so the well-tested
# indirect-block + fast-symlink read paths are exercised. 28 MiB of 1 KiB
# blocks comfortably holds the ~8 MiB minirootfs.
mke2fs -q -F -t ext2 -b 1024 \
  -O ^has_journal,^extent,^64bit,^metadata_csum,^dir_index,^resize_inode,^huge_file,^flex_bg,^ext_attr \
  -d "$WORK/root" "$OUT" 28672

echo "built $OUT ($(du -h "$OUT" | cut -f1)) — Alpine $ALPINE_REL rootfs"
echo "boot it: cargo xtask run-interactive --cmd distro_init --expect alpine-shell-ran"
