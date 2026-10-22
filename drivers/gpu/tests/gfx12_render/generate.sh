#!/bin/sh
# Offline, pinned actual RADV/ACO/Addrlib3 generator. Not part of the
# Linux-only */check.sh discovery: this requires separate explicit archives.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${MESA_ARCHIVE:?set MESA_ARCHIVE to pristine mesa-26.2.4.tar.xz}"
: "${LIBDRM_ARCHIVE:?set LIBDRM_ARCHIVE to pristine libdrm-2.4.134.tar.xz}"
: "${1:?provide a private build directory (normally under target)}"
work_dir=$(mkdir -p "$1" && CDPATH= cd -- "$1" && pwd)
if test -d "$work_dir/.git"; then echo 'refusing a repository root as build directory' >&2; exit 1; fi
python3 "$here/prepare.py" "$work_dir" "$MESA_ARCHIVE" "$LIBDRM_ARCHIVE"
meson setup "$work_dir/libdrm-build" "$work_dir/primary/libdrm-2.4.134" \
 --prefix="$work_dir/host" -Dtests=false -Dman-pages=disabled -Dvalgrind=disabled \
 -Dintel=disabled -Dradeon=disabled -Damdgpu=enabled -Dnouveau=disabled -Domap=disabled \
 -Dexynos=disabled -Dfreedreno=disabled -Dtegra=disabled -Dvc4=disabled -Detnaviv=disabled \
 --wrap-mode=nodownload
ninja -C "$work_dir/libdrm-build" -j2 install
export PKG_CONFIG_PATH="$work_dir/host/lib64/pkgconfig:$work_dir/host/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
meson setup "$work_dir/mesa-build" "$work_dir/primary/mesa-26.2.4" \
 -Dgallium-drivers=[] -Dvulkan-drivers=amd -Dplatforms=[] -Dglx=disabled -Degl=disabled \
 -Dopengl=false -Dgles1=disabled -Dgles2=disabled -Dllvm=disabled -Damd-use-llvm=false \
 -Dvideo-codecs=[] -Dbuild-tests=false -Dtools=drm-shim -Dglvnd=disabled --wrap-mode=nodownload
ninja -C "$work_dir/mesa-build" -j2 src/amd/vulkan/libvulkan_radeon.so \
 src/amd/drm-shim/libamdgpu_noop_drm_shim.so
export LD_LIBRARY_PATH="$work_dir/host/lib64:$work_dir/host/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_PRELOAD="$work_dir/mesa-build/src/amd/drm-shim/libamdgpu_noop_drm_shim.so"
export AMDGPU_GPU_ID=gfx1201 MESA_SHADER_CACHE_DISABLE=true RADV_DEBUG=nobinning
if test "${2-}" = --write; then
 python3 "$here/validate.py" "$work_dir" "$here/../../src/amdgpu_gfx12_draw_data.rs" --write
else
 test -z "${2-}" || { echo "unknown option: $2" >&2; exit 1; }
 python3 "$here/validate.py" "$work_dir" "$here/../../src/amdgpu_gfx12_draw_data.rs"
fi
