#!/usr/bin/env bash
# Rebuild the musl-static demo binary. Run from this directory.
#
# Requires: musl-gcc (Arch: `pacman -S musl`). Output is a static
# x86_64 ELF linked against musl; running it exercises the real
# musl init path (set_tid_address, rt_sigaction, brk, arch_prctl,
# ...) before reaching `main`. That's the actual end-to-end test
# of NARF's linux-compat ABI surface.
#
# -Wl,-L/usr/lib: GCC 16 emits `-latomic_asneeded` into the static
# link line; musl-gcc.specs only searches `/usr/lib/musl/lib`,
# where the static libatomic isn't present. Passing -L/usr/lib
# through to the linker lets it pick up the system static archive
# without dragging glibc into the link (libatomic.a alone has no
# glibc deps).
#
# Placement: -Ttext-segment=0x8000001000 keeps the PT_LOAD segments
# in PML4[1] where NARF's user range lives (init.ld; PML4[0] is
# kernel-shared with U=0). Same constraint hello_static_x86_64
# satisfies via raw ld.
set -euo pipefail
cd "$(dirname "$0")"

musl-gcc -static -no-pie -Os \
    -Wl,-L/usr/lib \
    -Wl,-Ttext-segment=0x8000001000 \
    -o hello_musl_x86_64 hello_musl_x86_64.c
strip --strip-all hello_musl_x86_64

size=$(stat -c %s hello_musl_x86_64)
echo "rebuilt hello_musl_x86_64: ${size} bytes"
