#!/bin/sh
# Exercise the unmodified upstream CLI against a real virtualized host PMU.
set -eu

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
cd "$ROOT"

if [ ! -e /dev/kvm ]; then
    echo "skip: /dev/kvm is unavailable"
    exit 0
fi

run_record() {
    mode=$1
    record_marker=$2
    XTASK_QEMU_NO_BALLOON=1 \
    NARF_QEMU_MEM_MB=2048 \
    XTASK_QEMU_ACCEL=kvm \
    NARF_QEMU_CPU=host \
    XTASK_RI_PROMPT_TIMEOUT_SECS=180 \
    XTASK_RI_ECHO_TIMEOUT_SECS=300 \
    cargo xtask run-interactive \
        --cmd "busybox chroot /mnt sh -c 'rm -f perf.data; perf record ${mode} -e cycles -- sleep 1 && test -s perf.data && echo ${record_marker}'" \
        --expect "$record_marker"

    XTASK_QEMU_NO_BALLOON=1 \
    NARF_QEMU_MEM_MB=2048 \
    XTASK_QEMU_ACCEL=kvm \
    NARF_QEMU_CPU=host \
    XTASK_RI_PROMPT_TIMEOUT_SECS=180 \
    XTASK_RI_ECHO_TIMEOUT_SECS=300 \
    cargo xtask run-interactive \
        --cmd "busybox chroot /mnt sh -c 'PERF_PAGER=cat perf report --stdio >/dev/null 2>&1 && echo ROK'" \
        --expect "ROK"
}

run_record "-c 100000" "PROK"
run_record "-F 1000" "FROK"
run_record "-a -c 1000000" "SYSROK"
