#!/bin/sh
# Rebuild the vendored static-musl `wl_input` — a two-process libwayland
# compositor+client exercising the **wl_seat** input-delivery path
# (wl_seat/wl_keyboard/wl_pointer) on a mapped xdg_toplevel. Rung 9 of
# docs/DESKTOP_LINUX_PLAN.md: a drawn window is useless if it can't receive
# input — this delivers a synthetic keypress + click to the focused window,
# and the keymap fd travels compositor→client (reverse-direction SCM_RIGHTS).
#
# Same libwayland build as REGEN_wl_handshake.sh, plus the xdg-shell protocol
# glue generated from the system wayland-protocols XML (output is
# arch-independent).
#
# Output: verification/data/musl-demo/wl_input_x86_64 (dynamic-musl PIE).
# Requires: musl-gcc, wayland-scanner, wayland-protocols (xdg-shell.xml),
# libffi + libwayland source, kernel UAPI headers (/usr/include/linux).
set -e

FFIVER=3.4.6
WLVER=1.23.0
XDG_XML=/usr/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml
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

printf '#define HAVE_ACCEPT4 1\n#define HAVE_MEMFD_CREATE 1\n#define _GNU_SOURCE 1\n' \
  | tee src/config.h > config.h
sed -e 's/@WAYLAND_VERSION_MAJOR@/1/g' -e 's/@WAYLAND_VERSION_MINOR@/23/g' \
    -e 's/@WAYLAND_VERSION_MICRO@/0/g' -e "s/@WAYLAND_VERSION@/$WLVER/g" \
    src/wayland-version.h.in > src/wayland-version.h

# Core Wayland protocol code.
wayland-scanner private-code  protocol/wayland.xml src/wayland-protocol.c
wayland-scanner client-header protocol/wayland.xml src/wayland-client-protocol.h
wayland-scanner server-header protocol/wayland.xml src/wayland-server-protocol.h
# xdg-shell protocol code (adds the xdg_* interfaces + send/dispatch glue).
wayland-scanner private-code  "$XDG_XML" src/xdg-shell-protocol.c
wayland-scanner client-header "$XDG_XML" src/xdg-shell-client-protocol.h
wayland-scanner server-header "$XDG_XML" src/xdg-shell-server-protocol.h

# Pass include paths inline (a multi-`-I` shell var can get mangled).
OBJS=""
for f in wayland-util wayland-os connection wayland-protocol \
         wayland-client wayland-server event-loop wayland-shm xdg-shell-protocol; do
  musl-gcc -O2 -fPIE -DHAVE_CONFIG_H \
    -Isrc -I. -I"$FFI_INC" -idirafter /usr/include \
    -c "src/$f.c" -o "$WORK/wl_$f.o"
  OBJS="$OBJS $WORK/wl_$f.o"
done

# The xdg-shell test ships alongside this script.
XDG_C="$(dirname "$0")/wl_input.c"
musl-gcc -O2 -fPIE -Isrc -I. -I"$FFI_INC" -idirafter /usr/include \
  -c "$XDG_C" -o "$WORK/wl_input.o"
musl-gcc -fPIE -pie -mcmodel=large "$WORK/wl_input.o" $OBJS "$FFI_A" -lm \
  -o wl_input_x86_64

echo "built: $WORK/wayland-$WLVER/wl_input_x86_64"
echo "copy it to verification/data/musl-demo/wl_input_x86_64"
