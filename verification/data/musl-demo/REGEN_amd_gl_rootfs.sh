#!/bin/sh
# Stage the from-source Mesa AMD build (REGEN_mesa_amd.sh) into a
# NARF-mountable Alpine rootfs: radeonsi + RADV for amdgpu nodes, with the
# software fallback (llvmpipe / kms_swrast / lavapipe) and the QEMU virgl
# driver intact. Same shape as REGEN_gl_rootfs.sh — Alpine edge via
# apk.static, packed with mke2fs -d, mounted by NARF at /mnt and entered with
# `chroot_run` — but every Mesa file Alpine's mesa-* packages install is
# replaced by the from-source build, so what runs is exactly what the recipe
# produced.
#
#   sh verification/data/musl-demo/REGEN_mesa_amd.sh        # once
#   sh verification/data/musl-demo/REGEN_amd_gl_rootfs.sh
#   NARF_VBLK_IMG=target/narf-amd-gl-vblk.img cargo xtask run-interactive \
#       --cmd "chroot_run /bin/busybox sh /mesa-amd-smoke.sh" \
#       --expect "MESA-AMD-OK"
#
# (add `--gpu-backend virgl --display egl-headless` to also cover a render
# node; the smoke passes on either backend.) Under QEMU there is no amdgpu
# device: the smoke proves the drivers load, enumerate through
# libdrm_amdgpu, decline every node cleanly, and that the software fallback
# still renders. On the RX 6750 XT the same script is the first on-hardware
# check (docs/MESA_AMD.md lists the rest).
#
#   MESA_AMD_HOST_CHECK=1   after building, also run /mesa-amd-smoke.sh in a
#                           user-namespace chroot on THIS host. On a Linux
#                           host with an amdgpu GPU that records the Linux
#                           reference ioctl trace for the same binaries
#                           (target/narf-mesa-amd/host-check.log).
#
# Output: target/narf-amd-gl-vblk.img (its own path; the default images are
# untouched). NOT committed. Requires: curl, tar, mke2fs (>= 1.43), network,
# and target/narf-mesa-amd/ from REGEN_mesa_amd.sh.
set -e

ALPINE=edge
ARCH=x86_64
CDN=https://dl-cdn.alpinelinux.org/alpine
MESA_VER=26.2.4

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
PKG="$ROOT/target/narf-mesa-amd"
TARBALL="$PKG/narf-mesa-amd-$MESA_VER-$ARCH.tar.gz"
OUT="$ROOT/target/narf-amd-gl-vblk.img"
[ -f "$TARBALL" ] || { echo "missing $TARBALL — run REGEN_mesa_amd.sh first" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "fetching apk.static"
IDX=$(curl -fsSL "$CDN/$ALPINE/main/$ARCH/" | grep -oE 'apk-tools-static-[0-9][^"]*\.apk' | head -1)
[ -n "$IDX" ] || { echo "could not find apk-tools-static in the index" >&2; exit 1; }
curl -fsSL -o "$WORK/apk.apk" "$CDN/$ALPINE/main/$ARCH/$IDX"
mkdir -p "$WORK/apk"
tar -xzf "$WORK/apk.apk" -C "$WORK/apk" 2>/dev/null
APK="$WORK/apk/sbin/apk.static"

RD="$WORK/root"
mkdir -p "$RD/etc/apk"
# Alpine's Mesa packages are installed only to pull in the exact runtime
# dependency closure of a Mesa 26.2.4 build (llvm23-libs, libelf, libxcb,
# wayland, ...); their files are removed again below. The clients are the
# on-hardware test vehicles: eglinfo/glxinfo (mesa-demos), vulkaninfo/vkcube
# (vulkan-tools), kmscube, and weston's DRM backend + simple-egl.
MESA_PKGS="mesa mesa-dri-gallium mesa-gbm mesa-egl mesa-gles mesa-gl \
    mesa-vulkan-ati mesa-vulkan-swrast mesa-vulkan-layers"
"$APK" --root "$RD" --arch "$ARCH" --initdb --usermode \
    -X "$CDN/$ALPINE/main" -X "$CDN/$ALPINE/community" \
    --allow-untrusted --no-cache \
    add alpine-baselayout busybox musl libdrm libpciaccess $MESA_PKGS \
    vulkan-loader vulkan-tools mesa-demos kmscube \
    weston weston-backend-drm weston-shell-desktop weston-clients \
    strace

echo "replacing Alpine's Mesa $MESA_VER files with the from-source build"
"$APK" --root "$RD" --usermode info -L $MESA_PKGS 2>/dev/null |
    grep -E '^(usr|etc)/' | sort -u > "$WORK/alpine-mesa-files"
while read -r f; do rm -f "$RD/$f"; done < "$WORK/alpine-mesa-files"
# Runtime files only: no headers, pkg-config, static libs.
tar -xzf "$TARBALL" -C "$RD" --exclude='./usr/include' --exclude='./usr/include/*' \
    --exclude='./usr/lib/pkgconfig' --exclude='./usr/lib/pkgconfig/*' \
    --exclude='./usr/share/pkgconfig' --exclude='./usr/share/pkgconfig/*' --exclude='*.a'
cp "$PKG/BUILDINFO" "$RD/etc/narf-mesa-amd.buildinfo"

# Every file of the build that must be present for the AMD path. A miss
# here is a packaging bug, not a runtime condition.
for f in usr/lib/libEGL.so.1 usr/lib/libgbm.so.1 usr/lib/libGLESv2.so.2 \
         usr/lib/libgallium-$MESA_VER.so usr/lib/libvulkan_radeon.so \
         usr/lib/libvulkan_lvp.so usr/lib/libdrm_amdgpu.so.1 usr/lib/libdrm.so.2 \
         usr/share/libdrm/amdgpu.ids usr/share/vulkan/icd.d/radeon_icd.$ARCH.json \
         usr/share/vulkan/icd.d/lvp_icd.$ARCH.json usr/bin/mesa_amd_probe \
         usr/lib/narf/narf_ioctl_trace.so; do
    [ -e "$RD/$f" ] || { echo "staged image is missing /$f" >&2; exit 1; }
done

cat > "$RD/mesa-amd-smoke.sh" <<'SMOKE'
#!/bin/busybox sh
# Mesa AMD smoke (milestone 9). Each step's stdout+stderr goes to the
# console; IOCTL lines are the LD_PRELOAD recorder (narf_ioctl_trace.so).
# Verdict lines: MESA-AMD-OK / MESA-AMD-FAIL, plus MESA-AMD-HW=<class> when
# an amdgpu node exists (amd = radeonsi rendered; anything else = fallback).
echo "MESA-AMD-SMOKE-START $(cat /etc/narf-mesa-amd.buildinfo 2>/dev/null | head -1)"
[ -e /proc/self ] || mount -t proc proc /proc 2>/dev/null
[ -d /sys/class ] || mount -t sysfs sysfs /sys 2>/dev/null
mkdir -p /tmp/mesa-amd && cd /tmp/mesa-amd
export HOME=/tmp/mesa-amd XDG_RUNTIME_DIR=/tmp/mesa-amd XDG_CACHE_HOME=/tmp/mesa-amd/cache
export EGL_LOG_LEVEL=info LIBGL_DEBUG=verbose MESA_LOG_LEVEL=info
TRACE=/usr/lib/narf/narf_ioctl_trace.so
ls -l /dev/dri 2>&1
FAIL=0

# step <name> <must-succeed:1|0> cmd...  — a signal (rc >= 128) always fails.
step() {
    name=$1; must=$2; shift 2
    echo "MESA-AMD-STEP $name begin"
    "$@" > "$name.log" 2>&1
    rc=$?
    cat "$name.log"
    if [ "$rc" -ge 128 ]; then
        echo "MESA-AMD-STEP $name CRASH rc=$rc"; FAIL=1
    elif [ "$must" = 1 ] && [ "$rc" != 0 ]; then
        echo "MESA-AMD-STEP $name FAIL rc=$rc"; FAIL=1
    else
        echo "MESA-AMD-STEP $name done rc=$rc"
    fi
}

step libs 1 /usr/bin/mesa_amd_probe libs
step drm 1 env LD_PRELOAD=$TRACE /usr/bin/mesa_amd_probe drm
AMD=$(sed -n 's/.*drm result amdgpu_nodes=\([0-9]*\).*/\1/p' drm.log)
[ -n "$AMD" ] || { echo "MESA-AMD-STEP drm no-result"; FAIL=1; AMD=0; }

step vk-radv 1 env LD_PRELOAD=$TRACE RADV_DEBUG=startup \
    VK_DRIVER_FILES=/usr/share/vulkan/icd.d/radeon_icd.x86_64.json /usr/bin/mesa_amd_probe vk
RADV=$(sed -n 's/.*vk result=ok devices=\([0-9]*\).*/\1/p' vk-radv.log)
# RADV opens render nodes only, so it can see at most the amdgpu nodes
# libdrm_amdgpu accepted (card + render node of one GPU count twice there).
if [ -z "$RADV" ] || { [ "$AMD" = 0 ] && [ "$RADV" != 0 ]; }; then
    echo "MESA-AMD-STEP vk-radv unexpected devices=$RADV amdgpu_nodes=$AMD"; FAIL=1
fi

step vk-lavapipe 1 env VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.x86_64.json /usr/bin/mesa_amd_probe vk
grep -q 'vk result=ok devices=[1-9]' vk-lavapipe.log || { echo "MESA-AMD-STEP vk-lavapipe no-device"; FAIL=1; }

# The compositor's view: GBM/EGL on every node with the loader's own choice.
step egl-default 1 env LD_PRELOAD=$TRACE /usr/bin/mesa_amd_probe egl
# radeonsi forced onto every node: on a non-amdgpu node the amdgpu winsys
# must refuse and EGL must fall back (or fail init) without crashing.
step egl-radeonsi 1 env LD_PRELOAD=$TRACE MESA_LOADER_DRIVER_OVERRIDE=radeonsi /usr/bin/mesa_amd_probe egl
if [ "$AMD" = 0 ] && grep -q 'class=amd' egl-radeonsi.log; then
    echo "MESA-AMD-STEP egl-radeonsi claims AMD rendering without an amdgpu node"; FAIL=1
fi
# The software fallback the desktop images use today. GBM decides its
# driver before EGL sees LIBGL_ALWAYS_SOFTWARE, so a compositor that must
# stay on the CPU renderer sets GBM_ALWAYS_SOFTWARE too.
step egl-swrast 1 env LIBGL_ALWAYS_SOFTWARE=1 GBM_ALWAYS_SOFTWARE=1 /usr/bin/mesa_amd_probe egl
if ! grep -q 'class=llvmpipe' egl-swrast.log ||
   grep 'class=' egl-swrast.log | grep -qv 'class=llvmpipe'; then
    echo "MESA-AMD-STEP egl-swrast not all llvmpipe"; FAIL=1
fi

if [ "$AMD" != 0 ]; then
    if grep -q 'class=amd' egl-default.log && grep -q 'driver=RADV' vk-radv.log; then
        echo "MESA-AMD-HW=amd radeonsi+RADV active"
    else
        echo "MESA-AMD-HW=fallback amdgpu node present but Mesa did not use it"
    fi
fi
echo "MESA-AMD-SUMMARY amdgpu_nodes=$AMD radv_devices=$RADV ioctls=$(cat *.log | grep -c '^IOCTL ')"
if [ "$FAIL" = 0 ]; then echo "MESA-AMD-OK"; else echo "MESA-AMD-FAIL"; fi
SMOKE
chmod +x "$RD/mesa-amd-smoke.sh"
# chroot_run's default payload.
ln -sf /mesa-amd-smoke.sh "$RD/probe.sh"

if [ "${MESA_AMD_HOST_CHECK:-0}" = 1 ]; then
    echo "running /mesa-amd-smoke.sh on this host (user-namespace chroot)"
    unshare --user --map-root-user --mount --fork /bin/sh -c '
        RD="$1"
        mkdir -p "$RD/dev" "$RD/proc" "$RD/sys" "$RD/tmp"
        mount --rbind /dev "$RD/dev"; mount --rbind /proc "$RD/proc"
        mount --rbind /sys "$RD/sys"; mount -t tmpfs tmpfs "$RD/tmp"
        exec chroot "$RD" /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            /bin/busybox sh /mesa-amd-smoke.sh
    ' -- "$RD" > "$PKG/host-check.log" 2>&1 || true
    grep -E '^MESA-AMD-(OK|FAIL|HW|SUMMARY)' "$PKG/host-check.log" || true
    echo "host check log: $PKG/host-check.log"
fi

# 1 GiB, 1 KiB blocks: LLVM (llvmpipe/lavapipe) + weston + the Mesa build
# come to ~450 MiB.
rm -f "$OUT"
mke2fs -q -F -t ext2 -d "$RD" -b 1024 "$OUT" 1048576
echo "built $OUT ($(du -h "$OUT" | cut -f1)); Mesa $MESA_VER radeonsi+RADV staged, swrast fallback intact"
