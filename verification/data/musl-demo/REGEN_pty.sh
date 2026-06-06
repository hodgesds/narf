#!/usr/bin/env bash
# Rebuild the PTY smoke musl demo binary. Run from this directory.
#
# Static against musl, linked at NARF's PML4[1] base (0x8000001000).
# Output is a 64-bit ELF the kernel can exec directly without
# touching /lib/ld-musl.
set -euo pipefail
cd "$(dirname "$0")"

musl-gcc -static -no-pie -Os \
    -Wl,-L/usr/lib \
    -Wl,-Ttext-segment=0x8000001000 \
    -Wl,--defsym=_DYNAMIC=0x8000001000 \
    -o pty_smoke_x86_64 pty_smoke_x86_64.c
strip --strip-all pty_smoke_x86_64

size=$(stat -c %s pty_smoke_x86_64)
echo "rebuilt pty_smoke_x86_64: ${size} bytes"
