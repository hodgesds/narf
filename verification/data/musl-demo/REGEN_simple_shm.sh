#!/bin/sh
# Rebuild the vendored dynamic-musl `simple_shm` — the UNMODIFIED upstream
# weston `clients/simple-shm.c` (weston tag 9.0.0, commit
# 04d3ae265d8d8f84352c8dac21ec40b2fe07e7d2). It is a minimal wl_shm +
# xdg-shell client: maps a 250x250 top-level window, allocates a sealed-memfd
# wl_shm pool, double-buffers, and paints an animated checkerboard driven by
# wl_surface frame callbacks.
#
# This proves a REAL, off-the-shelf Wayland client (not a hand-written NARF
# test) links libwayland-client + xdg-shell + a sealed-memfd shm pool and runs
# on NARF. It will be driven by a minimal compositor advertising:
#   wl_compositor (v4), wl_shm, xdg_wm_base (v1)
# over a named AF_UNIX socket. simple-shm binds wl_compositor@1, xdg_wm_base@1,
# wl_shm@1 (and optionally zwp_fullscreen_shell_v1@1 if xdg_wm_base is absent).
#
# Reuses the SAME libwayland 1.23.0 + libffi 3.4.6 build as REGEN_wl_xdg.sh:
# the prebuilt objects under /tmp/wlbuild/wl_*.o and the xdg-shell glue
# /tmp/wlbuild/wl_xdg-shell-protocol.o.  If those are gone, run
# REGEN_wl_xdg.sh first (it rebuilds libwayland + libffi from source).
#
# Output: verification/data/musl-demo/simple_shm_x86_64 (dynamic-musl PIE,
# interpreter /lib/ld-musl-x86_64.so.1).
# Requires: musl-gcc, wayland-scanner, curl, wayland-protocols
# (fullscreen-shell-unstable-v1.xml), the prebuilt /tmp/wlbuild objects,
# kernel UAPI headers (/usr/include/linux for memfd/seals).
set -e

WESTON_TAG=9.0.0
WESTON_COMMIT=04d3ae265d8d8f84352c8dac21ec40b2fe07e7d2
RAW=https://gitlab.freedesktop.org/wayland/weston/-/raw/$WESTON_TAG
FS_XML=/usr/share/wayland-protocols/unstable/fullscreen-shell/fullscreen-shell-unstable-v1.xml

# Prebuilt libwayland + libffi from the wl_xdg build (do NOT clobber).
WLBUILD=/tmp/wlbuild
WLSRC=$WLBUILD/wayland-1.23.0/src
FFI_INC=$WLBUILD/libffi-3.4.6/x86_64-pc-linux-musl/include
FFI_A=$WLBUILD/libffi-3.4.6/x86_64-pc-linux-musl/.libs/libffi.a
for o in wl_wayland-util wl_wayland-os wl_connection wl_wayland-protocol \
         wl_wayland-client wl_wayland-server wl_event-loop wl_wayland-shm \
         wl_xdg-shell-protocol; do
  [ -f "$WLBUILD/$o.o" ] || { echo "missing $WLBUILD/$o.o — run REGEN_wl_xdg.sh first"; exit 1; }
done
[ -f "$WLSRC/xdg-shell-client-protocol.h" ] || { echo "missing generated xdg-shell header in $WLSRC"; exit 1; }

WORK=$(mktemp -d)
cd "$WORK"

# --- fetch UNMODIFIED upstream weston sources ---
curl -sL -o simple-shm.c       "$RAW/clients/simple-shm.c"
curl -sL -o os-compatibility.c "$RAW/shared/os-compatibility.c"
curl -sL -o os-compatibility.h "$RAW/shared/os-compatibility.h"
# trivial calloc(1,size) wrapper that simple-shm.c + os-compatibility.c include
mkdir -p libweston shared
curl -sL -o libweston/zalloc.h "$RAW/include/libweston/zalloc.h"
cp os-compatibility.h shared/os-compatibility.h

# config.h: enable sealed memfd path (NARF supports memfd_create + F_ADD_SEALS).
printf '#define HAVE_MEMFD_CREATE 1\n#define HAVE_MKOSTEMP 1\n#define HAVE_POSIX_FALLOCATE 1\n#define _GNU_SOURCE 1\n' > config.h

# --- fullscreen-shell-unstable-v1 glue (simple-shm.c references its symbols) ---
wayland-scanner private-code  "$FS_XML" fullscreen-shell-unstable-v1-protocol.c
wayland-scanner client-header "$FS_XML" fullscreen-shell-unstable-v1-client-protocol.h

# --- compile (inline -I flags; a multi-`-I` shell var gets mangled here) ---
# dynamic-PIE + -mcmodel=large: a -static musl binary links at 0x400000 and
# collides with a NARF kernel huge page. -idirafter /usr/include finds
# linux/*.h UAPI (memfd seals) without shadowing musl's own headers.
musl-gcc -O2 -fPIE -DHAVE_CONFIG_H \
  -I. -I"$WLSRC" -I"$FFI_INC" -idirafter /usr/include \
  -c simple-shm.c -o simple-shm.o
musl-gcc -O2 -fPIE -DHAVE_CONFIG_H \
  -I. -I"$WLSRC" -I"$FFI_INC" -idirafter /usr/include \
  -c os-compatibility.c -o os-compatibility.o
musl-gcc -O2 -fPIE \
  -I. -I"$WLSRC" -I"$FFI_INC" -idirafter /usr/include \
  -c fullscreen-shell-unstable-v1-protocol.c -o fullscreen-shell-unstable-v1-protocol.o

# --- link: our objects first, then libwayland, then libffi, then -lm ---
musl-gcc -fPIE -pie -mcmodel=large \
  simple-shm.o os-compatibility.o fullscreen-shell-unstable-v1-protocol.o \
  "$WLBUILD/wl_wayland-util.o" \
  "$WLBUILD/wl_wayland-os.o" \
  "$WLBUILD/wl_connection.o" \
  "$WLBUILD/wl_wayland-protocol.o" \
  "$WLBUILD/wl_wayland-client.o" \
  "$WLBUILD/wl_wayland-server.o" \
  "$WLBUILD/wl_event-loop.o" \
  "$WLBUILD/wl_wayland-shm.o" \
  "$WLBUILD/wl_xdg-shell-protocol.o" \
  "$FFI_A" -lm \
  -o simple_shm_x86_64

file simple_shm_x86_64
echo "built: $WORK/simple_shm_x86_64"
echo "copy it to verification/data/musl-demo/simple_shm_x86_64"
