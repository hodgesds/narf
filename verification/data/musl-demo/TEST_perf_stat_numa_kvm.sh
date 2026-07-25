#!/bin/sh
# Exercise Linux perf's real system-wide NUMA aggregation against host PMU.
set -eu

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
cd "$ROOT"

if [ ! -e /dev/kvm ]; then
    echo "skip: /dev/kvm is unavailable"
    exit 0
fi

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

XTASK_QEMU_NO_BALLOON=1 \
NARF_QEMU_MEM_MB=2048 \
XTASK_QEMU_ACCEL=kvm \
NARF_QEMU_CPU=host \
XTASK_RI_PROMPT_TIMEOUT_SECS=180 \
XTASK_RI_ECHO_TIMEOUT_SECS=300 \
cargo xtask run-interactive \
    --cmd "busybox chroot /mnt sh -c 'perf stat -a -d --per-node -- sleep 1; echo PERF-NUMA-DONE'" \
    --expect PERF-NUMA-DONE >"$LOG" 2>&1

cat "$LOG"
! grep -q 'N-1' "$LOG"
grep '^N0.*cycles' "$LOG" | grep -qv 'not supported'
grep '^N1.*cycles' "$LOG" | grep -qv 'not supported'
