#!/bin/sh
# Rebuild the tmpfs MAP_SHARED coherence smoke.
#
# Statically linked on purpose: the dynamically-linked musl cases need
# /lib/ld-musl-x86_64.so.1 staged from the Alpine rootfs, and an
# environment without it cannot run them at all (the boot prints
# "boot-init: /lib mount skipped ... dynamic-linked binaries will fail to
# exec"). A static binary needs none of that.
#
# The binary is NOT committed: a static glibc build is ~780 KB, against
# ~20 KB for the musl cases beside it. Build it where you need it.
#
# Prefer musl if it is available, else plain gcc:
#
#   musl-gcc -static -O1 -o tmpfs_share_smoke_x86_64 tmpfs_share_smoke_x86_64.c
#   gcc      -static -no-pie -O1 -o tmpfs_share_smoke_x86_64 tmpfs_share_smoke_x86_64.c
#
# Then run it against NARF — note the guest path is NOT under /bin, which
# boot-init covers with a memfs mount that would shadow the staged file:
#
#   XTASK_STAGE_BIN=$PWD/tmpfs_share_smoke_x86_64:tmpfs_share \
#     cargo xtask run-interactive --cmd /tmpfs_share \
#       --expect tmpfs-share-ok --features boot-init,firmware-allow-unsigned
#
# It must also pass on the host's real Linux kernel: every assertion in it
# is a Linux semantic, so a failure there means the TEST is wrong.
set -eu
CC=${CC:-gcc}
$CC -static -no-pie -O1 -o tmpfs_share_smoke_x86_64 tmpfs_share_smoke_x86_64.c
echo "built tmpfs_share_smoke_x86_64"
