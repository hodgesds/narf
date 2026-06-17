#!/usr/bin/env bash
# Rebuild the committed `redis_server_x86_64` binary that NARF embeds and
# runs as a real off-box server daemon (the S2 server milestone).
#
# Recipe: an Alpine-style musl build of an UNMODIFIED redis 7.2.x —
#   * CC=musl-gcc                 — link against musl (NARF is musl-only).
#   * MALLOC=libc                 — use libc malloc, NOT the bundled
#                                   jemalloc (jemalloc fights musl + does
#                                   aggressive mmap/madvise the kernel
#                                   needn't support yet).
#   * BUILD_TLS=no                — drop the OpenSSL (libssl/libcrypto)
#                                   dependency so the only DT_NEEDED is
#                                   libc.so (resolved by ld-musl); keeps
#                                   the rootfs to just the binary + loader.
#   * strip --strip-all           — 10.5 MB -> ~2.9 MB for embedding.
#
# The result is a dynamic-PIE musl ELF (PT_INTERP=/lib/ld-musl-x86_64.so.1)
# that NARF loads via the same ld-musl path as the other dynamic smokes.
#
# Requires: musl-gcc, make, curl. Run from this directory.
set -euo pipefail
cd "$(dirname "$0")"

VER="${REDIS_VERSION:-7.2.5}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "fetching redis ${VER} source..."
curl -sL -o "$work/redis.tar.gz" \
    "https://github.com/redis/redis/archive/refs/tags/${VER}.tar.gz"
tar xzf "$work/redis.tar.gz" -C "$work"

echo "building redis-server (musl, MALLOC=libc, no TLS)..."
make -C "$work/redis-${VER}" -j"$(nproc)" \
    CC=musl-gcc MALLOC=libc BUILD_TLS=no >/dev/null

strip --strip-all "$work/redis-${VER}/src/redis-server"
cp "$work/redis-${VER}/src/redis-server" redis_server_x86_64

size=$(stat -c %s redis_server_x86_64)
echo "rebuilt redis_server_x86_64: ${size} bytes (redis ${VER})"
