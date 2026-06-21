#!/bin/sh
# Rebuild the vendored static-musl `modetest` (libdrm's KMS test tool) —
# a real third-party DRM client used to validate /dev/dri/card0 against
# the actual libdrm ioctl encodings (Rung 4 of docs/DESKTOP_LINUX_PLAN.md).
#
# Output: verification/data/musl-demo/modetest_x86_64  (dynamic-musl PIE,
# PT_INTERP=/lib/ld-musl-x86_64.so.1 — same load shape as the other musl
# smokes; a -static build links at 0x400000 and collides with a kernel
# huge-page mapping).
#
# Requires: musl-gcc, python3, and the kernel UAPI headers (/usr/include/linux).
set -e

VER=2.4.134
WORK=$(mktemp -d)
cd "$WORK"
curl -sL -o libdrm.tar.xz "https://dri.freedesktop.org/libdrm/libdrm-$VER.tar.xz"
tar xf libdrm.tar.xz
cd "libdrm-$VER"

# Minimal config.h (meson normally generates this).
cat > config.h <<'EOF'
#define MAJOR_IN_SYSMACROS 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SYSCTL_H 0
#define HAVE_VISIBILITY 1
#define HAVE_OPEN_MEMSTREAM 1
#define HAVE_SECURE_GETENV 1
#define UDEV 0
#define HAVE_CAIRO 0
#define _GNU_SOURCE 1
EOF

# Generated fourcc modifier table (meson custom_target).
python3 gen_table_fourcc.py include/drm/drm_fourcc.h generated_static_table_fourcc.h

INC="-I. -Iinclude/drm -Itests -Itests/util -Itests/modetest -idirafter /usr/include"
SRCS="xf86drm xf86drmHash xf86drmMode xf86drmRandom xf86drmSL \
      tests/util/format tests/util/kms tests/util/pattern \
      tests/modetest/buffers tests/modetest/cursor tests/modetest/modetest"
for f in $SRCS; do
  musl-gcc -O2 -fPIE -mcmodel=large -include config.h $INC -c "$f.c" -o "/tmp/m_$(basename $f).o"
done
musl-gcc -fPIE -pie -mcmodel=large /tmp/m_*.o -o modetest_x86_64
rm -f /tmp/m_*.o

echo "built: $WORK/libdrm-$VER/modetest_x86_64"
echo "copy it to verification/data/musl-demo/modetest_x86_64"
