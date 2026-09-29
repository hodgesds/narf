#!/bin/sh
# Build an Alpine rootfs with the REAL desktop GL stack — Mesa's virgl
# gallium driver, GBM, EGL/GLES — plus kmscube, the canonical minimal
# KMS+GBM+EGL client. This is the Mesa-in-guest counterpart of the
# hand-rolled `virgl3d_smoke`: kmscube exercises exactly what a
# compositor does (gbm_bo allocation, EGL on the GBM platform, GL
# rendering through Mesa→VIRTGPU ioctls, ADDFB2 + page-flips of
# GPU-rendered buffers) with none of a desktop's moving parts.
#
# NARF mounts the image (QEMU virtio-blk) at /mnt; `chroot_run` chroots
# into it:
#
#   sh verification/data/musl-demo/REGEN_gl_rootfs.sh
#   NARF_VBLK_IMG=target/narf-gl-vblk.img cargo xtask run-interactive \
#       --gpu-backend virgl --display egl-headless \
#       --cmd "chroot_run /bin/busybox sh /glcube.sh" --expect "GLCUBE-OK"
#
# Fully unprivileged: apk.static installs into a --root dir, mke2fs -d
# packs it. Output: target/narf-gl-vblk.img (selected via NARF_VBLK_IMG;
# the default stress image at narf-vblk.img is untouched). NOT committed.
# Requires: curl, tar, mke2fs (e2fsprogs >= 1.43 for `-d`), network.
set -e

ALPINE=v3.21
ARCH=x86_64
CDN=https://dl-cdn.alpinelinux.org/alpine

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-gl-vblk.img"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$ROOT/target"

# apk.static (apk-tools-static) — the unprivileged installer.
echo "fetching apk.static"
IDX=$(curl -fsSL "$CDN/$ALPINE/main/$ARCH/" | grep -oE 'apk-tools-static-[0-9][^"]*\.apk' | head -1)
[ -n "$IDX" ] || { echo "could not find apk-tools-static in the index" >&2; exit 1; }
curl -fsSL -o "$WORK/apk.apk" "$CDN/$ALPINE/main/$ARCH/$IDX"
mkdir -p "$WORK/apk"
tar -xzf "$WORK/apk.apk" -C "$WORK/apk" 2>/dev/null
APK="$WORK/apk/sbin/apk.static"

RD="$WORK/root"
mkdir -p "$RD/etc/apk"
echo "installing Mesa GL stack + kmscube into rootfs"
# mesa-dri-gallium carries virtio_gpu_dri.so (the virgl driver);
# mesa-gbm/mesa-egl/mesa-gles are the loader stack kmscube links.
# mesa-demos-egl ships eglinfo for diagnostics when the cube won't spin.
"$APK" --root "$RD" --arch "$ARCH" --initdb \
    -X "$CDN/$ALPINE/main" -X "$CDN/$ALPINE/community" \
    --allow-untrusted --no-cache \
    add alpine-baselayout busybox musl \
    libdrm mesa-dri-gallium mesa-gbm mesa-egl mesa-gles \
    kmscube mesa-demos strace

# The workload chroot_run runs. kmscube --count renders a fixed number of
# frames and exits 0; every frame is a full GL draw + gbm surface swap +
# KMS page-flip. The renderer line proves Mesa picked virgl (host GPU),
# not a software fallback.
cat > "$RD/glcube.sh" <<'GLCUBE'
echo "GLCUBE-START pid=$$"
export EGL_LOG_LEVEL=warning
export LIBGL_DEBUG=verbose
/usr/bin/kmscube --count=60 2>&1
RC=$?
echo "GLCUBE-RC=$RC"
if [ "$RC" = 0 ]; then
  echo "GLCUBE-OK"
else
  echo "GLCUBE-FAIL"
fi
GLCUBE
chmod +x "$RD/glcube.sh"

# Pack into an ext2 image (512 MiB, 1 KiB blocks — LLVM behind the
# gallium drivers makes this rootfs ~350 MiB).
mke2fs -q -F -t ext2 -d "$RD" -b 1024 "$OUT" 524288
echo "built $OUT ($(du -h "$OUT" | cut -f1)); kmscube + Mesa virgl present"
