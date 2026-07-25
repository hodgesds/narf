#!/bin/sh
# Rebuild the Alpine perf rootfs and run the unmodified CLI under NARF.
set -eu

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
"$ROOT/verification/data/musl-demo/REGEN_perf_rootfs.sh"

cd "$ROOT"

run_perf() {
    XTASK_QEMU_NO_BALLOON=1 \
    NARF_QEMU_MEM_MB=2048 \
    XTASK_RI_PROMPT_TIMEOUT_SECS=180 \
    XTASK_RI_ECHO_TIMEOUT_SECS=90 \
    cargo xtask run-interactive --cmd "$1" --expect "$2"
}

run_perf "busybox chroot /mnt perf stat -e '{cpu-clock,task-clock}' -- true" \
    "seconds time elapsed"
run_perf "busybox chroot /mnt perf stat -- true" "seconds time elapsed"
