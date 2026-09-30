#!/bin/sh
# Build an Alpine rootfs with the REAL desktop GL stack — Mesa's virgl
# gallium driver, GBM, EGL/GLES — plus kmscube and glmark2-drm. This is
# the Mesa-in-guest counterpart of the
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
# A protocol-shaped raw throughput run (30 independent processes, one warmup):
#
#   NARF_VBLK_IMG=target/narf-gl-vblk.img cargo xtask run-interactive \
#       --gpu-backend virgl --display egl-headless \
#       --cmd "chroot_run /bin/busybox sh /glmark2-bench.sh 30 5.0" \
#       --expect "GLMARK2-DONE"
#
# The script emits raw `GLMARK2-SAMPLE` rows only. Do not quote their average
# as a result: verification/specification/spec.md §8 still requires the host
# runner's median + 95% bootstrap CI + percentiles and the paired Linux-guest
# Welch/Mann-Whitney comparison (100 samples when CV > 5%).
#
# Fully unprivileged: apk.static installs into a --root dir, mke2fs -d
# packs it. Output: target/narf-gl-vblk.img (selected via NARF_VBLK_IMG;
# the default stress image at narf-vblk.img is untouched). NOT committed.
# Requires: curl, tar, mke2fs (e2fsprogs >= 1.43 for `-d`), network.
set -e

ALPINE=edge
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
# glmark2 currently lives in edge/testing, so the whole image intentionally
# uses edge: mixing its C++/Mesa dependencies with a stable rootfs risks ABI
# skew in what is only a disposable test vehicle.
"$APK" --root "$RD" --arch "$ARCH" --initdb \
    -X "$CDN/$ALPINE/main" -X "$CDN/$ALPINE/community" \
    -X "$CDN/$ALPINE/testing" \
    --allow-untrusted --no-cache \
    add alpine-baselayout busybox musl \
    libdrm mesa-dri-gallium mesa-gbm mesa-egl mesa-gles \
    kmscube glmark2 mesa-demos strace

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

# Raw samples for the NARF-vs-Linux throughput comparison. The build/VBO scene
# deliberately stresses short draw submission and fence turnover; immediate
# swap avoids a deliberate FIFO/vblank cap. Each measured sample is a fresh
# glmark2 process. One preceding process warms Mesa/virglrenderer caches.
cat > "$RD/glmark2-bench.sh" <<'GLMARK'
#!/bin/busybox sh
set -eu
export LC_ALL=C
export EGL_LOG_LEVEL=warning
export LIBGL_DEBUG=verbose

SAMPLES=${1:-30}
DURATION=${2:-5.0}
case "$SAMPLES" in
    ''|*[!0-9]*) echo "GLMARK2-FAIL invalid sample count: $SAMPLES"; exit 2 ;;
esac
if [ "$SAMPLES" -lt 30 ]; then
    echo "GLMARK2-FAIL verification protocol requires at least 30 samples"
    exit 2
fi

run_one() {
    /usr/bin/glmark2-drm \
        --winsys-options drm-device=/dev/dri/card0 \
        --swap-mode immediate --size 800x600 --results fps \
        --benchmark "build:duration=$DURATION:use-vbo=true" 2>&1
}

echo "GLMARK2-BEGIN benchmark=glmark2.build_vbo_fps unit=fps higher_is_better warmup=1 n=$SAMPLES delta_pct=5 duration_s=$DURATION"
WARMUP=$(run_one) || {
    printf '%s\n' "$WARMUP"
    echo "GLMARK2-FAIL warmup"
    exit 1
}
RENDERER=$(printf '%s\n' "$WARMUP" | sed -n 's/^[[:space:]]*GL_RENDERER:[[:space:]]*//p' | head -1)
LOWER_RENDERER=$(printf '%s' "$RENDERER" | tr '[:upper:]' '[:lower:]')
case "$LOWER_RENDERER" in
    *virgl*|*virtio*) ;;
    *)
        printf '%s\n' "$WARMUP"
        echo "GLMARK2-FAIL renderer=$RENDERER (expected virgl, refusing software fallback)"
        exit 1
        ;;
esac
echo "GLMARK2-RENDERER $RENDERER"

i=1
while [ "$i" -le "$SAMPLES" ]; do
    OUT=$(run_one) || {
        printf '%s\n' "$OUT"
        echo "GLMARK2-FAIL sample=$i"
        exit 1
    }
    SCORE=$(printf '%s\n' "$OUT" | awk '/glmark2 Score:/ { value=$NF } END { print value }')
    case "$SCORE" in
        ''|*[!0-9.]*)
            printf '%s\n' "$OUT"
            echo "GLMARK2-FAIL unparseable-score sample=$i score=$SCORE"
            exit 1
            ;;
    esac
    echo "GLMARK2-SAMPLE index=$i fps=$SCORE"
    i=$((i + 1))
done
echo "GLMARK2-DONE n=$SAMPLES"
GLMARK
chmod +x "$RD/glmark2-bench.sh"

# Linux-reference init for the SAME image, Mesa build, renderer backend, and
# glmark2 workload used by NARF. Boot the image as /dev/vda with
# `root=/dev/vda rw rootfstype=ext4 init=/glmark2-linux-init.sh`; optional
# `glmark_samples=N glmark_duration=S` kernel arguments select the raw sample
# count and per-process scene duration. The init exits only after emitting a
# machine-readable terminal marker, so a serial harness can stop QEMU there.
cat > "$RD/glmark2-linux-init.sh" <<'LINUX_INIT'
#!/bin/busybox sh
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

SAMPLES=30
DURATION=5.0
for arg in $(cat /proc/cmdline); do
    case "$arg" in
        glmark_samples=*) SAMPLES=${arg#glmark_samples=} ;;
        glmark_duration=*) DURATION=${arg#glmark_duration=} ;;
    esac
done

echo "GLMARK2-LINUX-BEGIN kernel=$(uname -r)"
/bin/busybox sh /glmark2-bench.sh "$SAMPLES" "$DURATION"
RC=$?
echo "GLMARK2-LINUX-RC=$RC"
echo GLMARK2-LINUX-DONE
sync
poweroff -f 2>/dev/null || true
exit "$RC"
LINUX_INIT
chmod +x "$RD/glmark2-linux-init.sh"

# Pack into an ext2 image (512 MiB, 1 KiB blocks — LLVM behind the
# gallium drivers makes this rootfs ~350 MiB).
mke2fs -q -F -t ext2 -d "$RD" -b 1024 "$OUT" 524288
echo "built $OUT ($(du -h "$OUT" | cut -f1)); kmscube + glmark2-drm + Mesa virgl present"
