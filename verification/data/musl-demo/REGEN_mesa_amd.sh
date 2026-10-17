#!/bin/sh
# Build Mesa 26.2.4 with the AMD hardware drivers — gallium radeonsi, Vulkan
# RADV, the amdgpu winsys, libdrm_amdgpu 2.4.134 — for NARF's musl userspace
# (milestone 9 of the Navi22 / RX 6750 XT bring-up).
#
# NARF runs distro Mesa unmodified: the GL image (REGEN_gl_rootfs.sh) and the
# KDE images install Alpine edge's musl Mesa, and the vendored `modetest`
# (REGEN_modetest.sh) is built from the pristine libdrm 2.4.134 tarball. This
# recipe keeps both conventions: the pristine upstream tarballs (sha256-pinned
# below), built inside an Alpine edge build root — the same libc, toolchain
# and LLVM that produced the Alpine Mesa package the images already run — so
# the result is a drop-in replacement for Alpine's mesa-* packages, ABI and
# file layout included. Nothing it produces is committed.
#
#   sh verification/data/musl-demo/REGEN_mesa_amd.sh
#   sh verification/data/musl-demo/REGEN_amd_gl_rootfs.sh   # stage into an image
#
# Driver choices (details: docs/MESA_AMD.md):
#   radeonsi + RADV    -Damd-use-llvm=false: both compile shaders with ACO
#                      only. Mesa 26.2 no longer needs LLVM for either AMD
#                      driver; with amd-use-llvm=true it would demand
#                      LLVM >= 18 and route radeonsi compute/some stages
#                      through the AMDGPU LLVM backend.
#   llvmpipe/softpipe  The existing software fallback (kms_swrast, swrast,
#                      LIBGL_ALWAYS_SOFTWARE=1). llvmpipe is the only reason
#                      LLVM (shared libLLVM, Alpine llvm23) is linked at all.
#   lavapipe           Vulkan software fallback (VK swrast).
#   virgl              Keeps the QEMU virgl path (REGEN_gl_rootfs.sh) working
#                      when this build replaces Alpine's.
#   amdgpu-virtio      As Alpine builds it: radeonsi/RADV over a virtio-gpu
#                      DRM native context (XTASK_GPU_DRM_NATIVE=1).
#   gallium-va         VA-API for radeonsi (/usr/lib/dri/radeonsi_drv_video.so)
#                      over the VCN 3.0 decode/encode and JPEG 3.0 rings, with
#                      every codec (-Dvideo-codecs=all, as Alpine builds it).
#                      RADV's Vulkan video (VK_KHR_video_decode/encode_*)
#                      comes with the same codec list. libva is Alpine's.
#
# Output (target/ is git-ignored):
#   target/narf-mesa-amd/narf-mesa-amd-26.2.4-x86_64.tar.gz  install tree
#   target/narf-mesa-amd/MANIFEST.sha256   per-file hashes of that tree
#   target/narf-mesa-amd/BUILDINFO         source hashes, meson options,
#                                          every build-root package version
#
# Environment:
#   MESA_AMD_WORK=<dir>   build root + sources (default target/mesa-amd-work).
#                         Untrusted third-party source is extracted only here.
#   MESA_AMD_JOBS=<n>     ninja -j (default: half the CPUs)
#   MESA_AMD_REBUILD=1    discard the build root and start clean
#
# Fully unprivileged: apk.static populates the build root; the compile runs
# chrooted in a user namespace (`unshare --map-root-user`).
# Requires: curl, tar, sha256sum, unshare (util-linux), network.
set -e

MESA_VER=26.2.4
MESA_SHA256=bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9
LIBDRM_VER=2.4.134
LIBDRM_SHA256=ac5e74d157830eb8bee44c6a6bf3ad49774ef0dd2a72bdad74a8f20308b52a95
ALPINE=edge
ARCH=x86_64
CDN=https://dl-cdn.alpinelinux.org/alpine

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
HERE="$ROOT/verification/data/musl-demo"
WORK="${MESA_AMD_WORK:-$ROOT/target/mesa-amd-work}"
OUT="$ROOT/target/narf-mesa-amd"
JOBS="${MESA_AMD_JOBS:-$(( ($(nproc) + 1) / 2 ))}"
BR="$WORK/buildroot"

mkdir -p "$WORK/dl" "$OUT"
[ "${MESA_AMD_REBUILD:-0}" = 1 ] && rm -rf "$BR"

# ------------------------------------------------------------- sources ---
fetch() { # url file sha256
    if [ ! -f "$WORK/dl/$2" ]; then
        echo "fetching $1"
        curl -fsSL -o "$WORK/dl/$2.part" "$1"
        mv "$WORK/dl/$2.part" "$WORK/dl/$2"
    fi
    echo "$3  $WORK/dl/$2" | sha256sum -c - >/dev/null || {
        echo "sha256 mismatch for $2" >&2; exit 1; }
}
fetch "https://archive.mesa3d.org/mesa-$MESA_VER.tar.xz" "mesa-$MESA_VER.tar.xz" "$MESA_SHA256"
fetch "https://dri.freedesktop.org/libdrm/libdrm-$LIBDRM_VER.tar.xz" "libdrm-$LIBDRM_VER.tar.xz" "$LIBDRM_SHA256"

# ---------------------------------------------------------- build root ---
if [ ! -x "$BR/usr/bin/meson" ]; then
    echo "fetching apk.static"
    IDX=$(curl -fsSL "$CDN/$ALPINE/main/$ARCH/" | grep -oE 'apk-tools-static-[0-9][^"]*\.apk' | head -1)
    [ -n "$IDX" ] || { echo "could not find apk-tools-static in the index" >&2; exit 1; }
    rm -rf "$WORK/apk" && mkdir -p "$WORK/apk"
    curl -fsSL -o "$WORK/apk.apk" "$CDN/$ALPINE/main/$ARCH/$IDX"
    tar -xzf "$WORK/apk.apk" -C "$WORK/apk" 2>/dev/null
    mkdir -p "$BR/etc/apk"
    # Build dependencies of Alpine's mesa APKBUILD (llvm23, as Alpine's
    # 26.2.4-r1), minus the rusticl/clang/cbindgen ones this configuration
    # does not use, plus vulkan-headers for the probes; libva-dev for
    # gallium-va.
    # --usermode: apk-tools 3 refuses to create a database as non-root
    # otherwise; every file is owned by the invoking user, which is root
    # inside the build namespace below.
    "$WORK/apk/sbin/apk.static" --root "$BR" --arch "$ARCH" --initdb --usermode \
        -X "$CDN/$ALPINE/main" -X "$CDN/$ALPINE/community" \
        --allow-untrusted --no-cache \
        add alpine-baselayout busybox musl build-base binutils pkgconf \
        meson ninja python3 py3-mako py3-packaging py3-ply py3-yaml py3-cparser \
        bison flex gettext findutils \
        llvm23-dev elfutils-dev eudev-dev expat-dev zlib-dev zstd-dev \
        libpciaccess-dev libxml2-dev glslang glslang-dev spirv-tools-dev \
        libdisplay-info-dev wayland-dev wayland-protocols \
        libx11-dev libxext-dev libxfixes-dev libxrandr-dev libxxf86vm-dev \
        libxdamage-dev libxshmfence-dev libxcb-dev xorgproto \
        vulkan-loader-dev vulkan-headers libva-dev
fi
# Build roots made before VA-API was enabled lack libva-dev.
if [ ! -f "$BR/usr/include/va/va.h" ]; then
    "$WORK/apk/sbin/apk.static" --root "$BR" --arch "$ARCH" --usermode \
        -X "$CDN/$ALPINE/main" -X "$CDN/$ALPINE/community" \
        --allow-untrusted --no-cache add libva-dev
fi

# A fresh copy of the sources each run, so an aborted build never leaves a
# half-patched tree behind; build dirs are kept for incremental rebuilds.
rm -rf "$BR/src" && mkdir -p "$BR/src" "$BR/probes"
tar -xJf "$WORK/dl/mesa-$MESA_VER.tar.xz" -C "$BR/src"
tar -xJf "$WORK/dl/libdrm-$LIBDRM_VER.tar.xz" -C "$BR/src"
cp "$HERE/mesa_amd_probe.c" "$HERE/narf_ioctl_trace.c" "$BR/probes/"
cp -f /etc/resolv.conf "$BR/etc/resolv.conf" 2>/dev/null || true

# Meson options, recorded verbatim in BUILDINFO. Mirrors Alpine's APKBUILD
# (prefix, dri path, platforms, shared LLVM, -O2 -g1, b_ndebug) except for
# the driver list and amd-use-llvm.
MESA_OPTS="--prefix=/usr --libdir=lib --sysconfdir=/etc --localstatedir=/var
 --buildtype=plain --wrap-mode=nofallback
 -Db_ndebug=true -Db_lto=false
 -Dplatforms=x11,wayland -Degl=enabled -Dgbm=enabled -Dglx=dri -Dopengl=true
 -Dgles1=enabled -Dgles2=enabled
 -Dgallium-drivers=radeonsi,llvmpipe,softpipe,virgl
 -Dvulkan-drivers=amd,swrast -Dvulkan-layers=device-select
 -Damd-use-llvm=false -Damdgpu-virtio=true
 -Dllvm=enabled -Dshared-llvm=enabled
 -Dgallium-va=enabled -Dgallium-rusticl=false -Dvideo-codecs=all
 -Dexpat=enabled -Dzstd=enabled -Dshader-cache=enabled -Dxmlconfig=enabled
 -Dallow-kcmp=enabled -Dxlib-lease=enabled
 -Ddri-drivers-path=/usr/lib/dri -Dbuild-tests=false"
LIBDRM_OPTS="--prefix=/usr --libdir=lib --buildtype=plain --wrap-mode=nofallback
 -Damdgpu=enabled -Dradeon=enabled -Dintel=enabled -Dnouveau=enabled
 -Dvmwgfx=enabled -Domap=disabled -Dexynos=disabled -Dfreedreno=disabled
 -Dtegra=disabled -Dvc4=disabled -Detnaviv=disabled
 -Dudev=true -Dvalgrind=disabled -Dcairo-tests=disabled -Dman-pages=disabled
 -Dtests=true -Dinstall-test-programs=true"

cat > "$BR/build.sh" <<EOF
#!/bin/sh
set -e
export PATH=/usr/lib/llvm23/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CFLAGS="-O2 -g1" CXXFLAGS="-O2 -g1"
rm -rf /stage && mkdir -p /stage

# libdrm first: it is installed into the build root too (same version as
# Alpine's libdrm-dev, so this only replaces identical files) and Mesa
# links against exactly this libdrm_amdgpu.
cd /src/libdrm-$LIBDRM_VER
[ -f /bld/libdrm/build.ninja ] || meson setup /bld/libdrm . $(echo $LIBDRM_OPTS)
ninja -C /bld/libdrm -j $JOBS
DESTDIR=/stage meson install -C /bld/libdrm --no-rebuild --quiet
meson install -C /bld/libdrm --no-rebuild --quiet

cd /src/mesa-$MESA_VER
# A build dir configured with other options (e.g. before VA-API) starts over.
cmp -s /bld/mesa.opts /bld/mesa.opts.want 2>/dev/null || rm -rf /bld/mesa
[ -f /bld/mesa/build.ninja ] || meson setup /bld/mesa . $(echo $MESA_OPTS)
cp /bld/mesa.opts.want /bld/mesa.opts
meson configure --no-pager /bld/mesa > /bld/mesa-configure.txt
ninja -C /bld/mesa -j $JOBS
DESTDIR=/stage meson install -C /bld/mesa --no-rebuild --quiet
meson install -C /bld/mesa --no-rebuild --quiet

# NARF probes, built against the just-installed libraries (see
# mesa_amd_probe.c / narf_ioctl_trace.c in verification/data/musl-demo).
mkdir -p /stage/usr/bin /stage/usr/lib/narf
cc -O2 -g -Wall -Wextra -DNARF_MESA_VER=\"$MESA_VER\" -o /stage/usr/bin/mesa_amd_probe /probes/mesa_amd_probe.c \
   -I/usr/include/libdrm -ldrm -ldrm_amdgpu -lEGL -lGLESv2 -lgbm -lvulkan -lva -lva-drm -ldl
cc -O2 -g -Wall -Wextra -shared -fPIC -o /stage/usr/lib/narf/narf_ioctl_trace.so \
   /probes/narf_ioctl_trace.c -I/usr/include/libdrm -ldl

apk info -v 2>/dev/null | sort > /stage-buildroot-packages.txt
EOF
chmod +x "$BR/build.sh"
mkdir -p "$BR/bld"
printf '%s\n' "$MESA_OPTS" > "$BR/bld/mesa.opts.want"

echo "building libdrm $LIBDRM_VER + Mesa $MESA_VER in the Alpine $ALPINE build root (-j$JOBS)"
unshare --user --map-root-user --mount --fork /bin/sh -c '
    set -e
    BR="$1"
    for d in dev proc sys; do mkdir -p "$BR/$d"; done
    mount --rbind /dev "$BR/dev"
    mount --rbind /proc "$BR/proc"
    mount --rbind /sys "$BR/sys"
    exec chroot "$BR" /usr/bin/env -i HOME=/root TERM=dumb LANG=C.UTF-8 /bin/sh /build.sh
' -- "$BR"

# ------------------------------------------------------------- package ---
TARBALL="$OUT/narf-mesa-amd-$MESA_VER-$ARCH.tar.gz"
( cd "$BR/stage" && find . \( -type f -o -type l \) | LC_ALL=C sort > "$WORK/filelist" &&
  tar --numeric-owner --owner=0 --group=0 --mtime=@0 --no-recursion \
      -czf "$TARBALL" -T "$WORK/filelist" )
( cd "$BR/stage" && find . -type f | LC_ALL=C sort | xargs sha256sum ) > "$OUT/MANIFEST.sha256"
{
    echo "mesa $MESA_VER sha256=$MESA_SHA256"
    echo "libdrm $LIBDRM_VER sha256=$LIBDRM_SHA256"
    echo "alpine $ALPINE $ARCH"
    echo "built $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "--- mesa meson options"; echo "$MESA_OPTS"
    echo "--- libdrm meson options"; echo "$LIBDRM_OPTS"
    echo "--- build-root packages"; cat "$BR/stage-buildroot-packages.txt"
} > "$OUT/BUILDINFO"
echo "built $TARBALL ($(du -h "$TARBALL" | cut -f1), $(wc -l < "$OUT/MANIFEST.sha256") files)"
