#!/usr/bin/env bash
# Build the mt-echo server (musl-static, for NARF) + the host loadgen,
# and verify the server is a static ELF.
#
# Requires: musl-gcc (Arch: `pacman -S musl`; here at
# /usr/local/bin/musl-gcc) and a host C compiler.
#
# NOTE ON THE LINK RECIPE
# -----------------------
# The committed musl-demo binaries (hello_musl_x86_64) were built on a
# toolchain whose GCC defaulted to NON-PIE, so plain `-static -no-pie`
# selected the non-PIE crt1.o. THIS host's GCC defaults to PIE and its
# musl-gcc.specs hardcodes the PIE startup (`Scrt1.o` + `crtbeginS.o`),
# which cannot be linked at the high NARF text address (-Ttext-segment
# 0x8000001000) because _start's PC32 reloc against _DYNAMIC overflows.
#
# We therefore drive the startup objects explicitly:
#   -nostartfiles + crt1.o/crti.o ... crtn.o     (non-PIE crt)
#   -mcmodel=large                                (high VA: 32-bit
#                                                  abs relocs to
#                                                  .rodata/.bss would
#                                                  otherwise overflow)
#   -Wl,--defsym=_DYNAMIC=0x8000001000            (crt1.o references
#                                                  _DYNAMIC; for a
#                                                  static no-PIE binary
#                                                  it is never
#                                                  dereferenced, but it
#                                                  must resolve near
#                                                  .text for the PC32
#                                                  reloc — same trick
#                                                  REGEN_pthread.sh uses)
#   -Wl,-Ttext-segment=0x8000001000               (PML4[1] user range)
set -euo pipefail
cd "$(dirname "$0")"

MUSL_GCC="${MUSL_GCC:-musl-gcc}"
HOST_CC="${HOST_CC:-cc}"
MUSL_LIB="${MUSL_LIB:-/usr/local/musl/lib}"
TEXT_ADDR="${TEXT_ADDR:-0x8000001000}"

echo "== building mt_echo_server_x86_64 (static musl) =="
"$MUSL_GCC" -nostartfiles -static -no-pie -fno-pie -O2 -pthread -mcmodel=large \
    "$MUSL_LIB/crt1.o" "$MUSL_LIB/crti.o" \
    mt_echo_server.c \
    "$MUSL_LIB/crtn.o" \
    -Wl,-L/usr/lib \
    -Wl,--defsym=_DYNAMIC="$TEXT_ADDR" \
    -Wl,-Ttext-segment="$TEXT_ADDR" \
    -o mt_echo_server_x86_64
strip --strip-all mt_echo_server_x86_64 || true

echo "== building loadgen (host) =="
"$HOST_CC" -O2 -pthread -o loadgen loadgen.c

echo
echo "== verify: file =="
file mt_echo_server_x86_64
echo "== verify: ldd =="
ldd mt_echo_server_x86_64 2>&1 || true

file_out="$(file mt_echo_server_x86_64)"
ldd_out="$(ldd mt_echo_server_x86_64 2>&1 || true)"
case "$file_out" in
    *"statically linked"*) ;;
    *) echo "FAIL: mt_echo_server is not statically linked"; exit 1 ;;
esac
case "$ldd_out" in
    *"not a dynamic executable"*) ;;
    *) echo "FAIL: ldd reports dynamic dependencies"; exit 1 ;;
esac

size=$(stat -c %s mt_echo_server_x86_64)
echo "OK: mt_echo_server_x86_64 is static (${size} bytes)"
echo "OK: loadgen built"
