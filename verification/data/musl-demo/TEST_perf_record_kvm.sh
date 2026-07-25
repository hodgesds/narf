#!/bin/sh
# Exercise the unmodified upstream CLI against a real virtualized host PMU.
set -eu

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
cd "$ROOT"

if [ ! -e /dev/kvm ]; then
    echo "skip: /dev/kvm is unavailable"
    exit 0
fi

XTASK_QEMU_NO_BALLOON=1 \
NARF_QEMU_MEM_MB=2048 \
XTASK_QEMU_ACCEL=kvm \
NARF_QEMU_CPU=host \
XTASK_RI_PROMPT_TIMEOUT_SECS=180 \
XTASK_RI_ECHO_TIMEOUT_SECS=300 \
cargo xtask run-interactive \
    --cmd "busybox chroot /mnt /bin/sh -c 'perf record -e cycles -- /bin/busybox dd if=/dev/zero of=/dev/null bs=1048576 count=1024; perf report --stdio'" \
    --expect "# Samples:"
