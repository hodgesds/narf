#!/usr/bin/env bash
# Rebuild the demo binary from source. Run from this directory.
#
# Requires: GNU binutils (as + ld). No libc, no musl-gcc, no cross
# toolchain. Output is a static x86_64 ELF using only direct Linux
# syscalls — proves NARF's linux-compat ABI dispatch end-to-end.
set -euo pipefail
cd "$(dirname "$0")"

as --64 -o hello_static_x86_64.o hello_static_x86_64.S
# Link at the NARF user-vaddr base (PML4[1]). The default ld
# layout puts PT_LOAD at 0x400000, which falls in PML4[0] — NARF
# copies that slot from the kernel's CR3 with U=0, so user-mode
# access faults. `init.ld` calls out the same address explicitly.
ld -static -nostdlib -z noexecstack \
    -Ttext-segment=0x8000001000 \
    -o hello_static_x86_64 hello_static_x86_64.o
strip --strip-all hello_static_x86_64
rm -f hello_static_x86_64.o

size=$(stat -c %s hello_static_x86_64)
echo "rebuilt hello_static_x86_64: ${size} bytes"
