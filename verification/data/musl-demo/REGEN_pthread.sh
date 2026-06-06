#!/usr/bin/env bash
# Rebuild the pthread musl demo binary. Run from this directory.
#
# Requires: musl-gcc (Arch: `pacman -S musl`). Output is a dynamic-
# linked x86_64 ELF — same shape as hello_musl_dyn but with
# -lpthread (no-op on musl since pthread is inside libc.so) and the
# extra -mcmodel=large for any per-thread TLS access patterns.
set -euo pipefail
cd "$(dirname "$0")"

musl-gcc -no-pie -Os -pthread \
    -Wl,-L/usr/lib \
    -Wl,--defsym=_DYNAMIC=0x8000001000 \
    -Wl,-Ttext-segment=0x8000001000 \
    -o hello_pthread_x86_64 hello_pthread_x86_64.c
strip --strip-all hello_pthread_x86_64

size=$(stat -c %s hello_pthread_x86_64)
echo "rebuilt hello_pthread_x86_64: ${size} bytes"
