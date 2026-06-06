#!/usr/bin/env bash
# Rebuild the dynamic musl demo binary. Run from this directory.
#
# Requires: musl-gcc (Arch: `pacman -S musl`). Output is a
# dynamic-linked x86_64 ELF — its PT_INTERP points at
# `/lib/ld-musl-x86_64.so.1`, which NARF stages into a kernel-side
# MemFs at /lib/. The kernel ELF loader (Wave-75) reads PT_INTERP,
# loads ld-musl at INTERP_BIAS, applies relocations, and jumps to
# ld-musl's entry; ld-musl then processes the program's relocations
# and runs `__libc_start_main → main`.
#
# Same -Wl,-Ttext-segment + --defsym=_DYNAMIC layout as the static
# build so the program lands in NARF's PML4[1] user range.
set -euo pipefail
cd "$(dirname "$0")"

musl-gcc -no-pie -Os \
    -Wl,-L/usr/lib \
    -Wl,--defsym=_DYNAMIC=0x8000001000 \
    -Wl,-Ttext-segment=0x8000001000 \
    -o hello_musl_dyn_x86_64 hello_musl_dyn_x86_64.c
strip --strip-all hello_musl_dyn_x86_64

size=$(stat -c %s hello_musl_dyn_x86_64)
echo "rebuilt hello_musl_dyn_x86_64: ${size} bytes"
