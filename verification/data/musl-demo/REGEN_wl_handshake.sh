#!/bin/sh
# Rebuild the vendored static-musl `wl_handshake` — a minimal libwayland
# client+server registry handshake over a socketpair. Rung 7 of
# docs/DESKTOP_LINUX_PLAN.md: proves the Wayland wire protocol + transport
# work on NARF (AF_UNIX sockets + SCM_RIGHTS + libffi marshalling + epoll).
#
# Output: verification/data/musl-demo/wl_handshake_x86_64 (dynamic-musl PIE).
# Requires: musl-gcc, wayland-scanner, python3, libffi + libwayland source,
# and the kernel UAPI headers (/usr/include/linux).
set -e

FFIVER=3.4.6
WLVER=1.23.0
WORK=$(mktemp -d)
cd "$WORK"

# --- libffi (static-musl) ---
curl -sL -o libffi.tar.gz \
  "https://github.com/libffi/libffi/releases/download/v$FFIVER/libffi-$FFIVER.tar.gz"
tar xf libffi.tar.gz
( cd "libffi-$FFIVER"
  ./configure CC=musl-gcc CFLAGS="-O2 -idirafter /usr/include" \
      --enable-static --disable-shared --disable-docs >/dev/null
  make -j"$(nproc)" >/dev/null )
FFI_INC="$WORK/libffi-$FFIVER/x86_64-pc-linux-musl/include"
FFI_A="$WORK/libffi-$FFIVER/x86_64-pc-linux-musl/.libs/libffi.a"

# --- libwayland ---
curl -sL -o wayland.tar.xz \
  "https://gitlab.freedesktop.org/wayland/wayland/-/releases/$WLVER/downloads/wayland-$WLVER.tar.xz"
tar xf wayland.tar.xz
cd "wayland-$WLVER"

# config.h + wayland-version.h (meson normally generates these).
printf '#define HAVE_ACCEPT4 1\n#define HAVE_MEMFD_CREATE 1\n#define _GNU_SOURCE 1\n' \
  | tee src/config.h > config.h
sed -e 's/@WAYLAND_VERSION_MAJOR@/1/g' -e 's/@WAYLAND_VERSION_MINOR@/23/g' \
    -e 's/@WAYLAND_VERSION_MICRO@/0/g' -e "s/@WAYLAND_VERSION@/$WLVER/g" \
    src/wayland-version.h.in > src/wayland-version.h

# Generated protocol code (host wayland-scanner; output is arch-independent).
wayland-scanner private-code  protocol/wayland.xml src/wayland-protocol.c
wayland-scanner client-header protocol/wayland.xml src/wayland-client-protocol.h
wayland-scanner server-header protocol/wayland.xml src/wayland-server-protocol.h

INC="-Isrc -I. -I$FFI_INC -idirafter /usr/include"
OBJS=""
for f in wayland-util wayland-os connection wayland-protocol \
         wayland-client wayland-server event-loop wayland-shm; do
  musl-gcc -O2 -fPIE -DHAVE_CONFIG_H $INC -c "src/$f.c" -o "$WORK/wl_$f.o"
  OBJS="$OBJS $WORK/wl_$f.o"
done

# The handshake test ships alongside this script.
HS="$(dirname "$0")/wl_handshake.c"
musl-gcc -O2 -fPIE $INC -c "$HS" -o "$WORK/wl_handshake.o"
musl-gcc -fPIE -pie -mcmodel=large "$WORK/wl_handshake.o" $OBJS "$FFI_A" -lm \
  -o wl_handshake_x86_64

echo "built: $WORK/wayland-$WLVER/wl_handshake_x86_64"
echo "copy it to verification/data/musl-demo/wl_handshake_x86_64"
