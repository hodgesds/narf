#!/bin/sh
# Collect raw cache-efficiency samples for NARF's /proc/interrupts reader.
#
# Run this once on the baseline and once on the candidate, then analyse the
# raw logs under verification/specification/spec.md §8.  This collector does
# not publish a performance result itself: a perf event that a virtual PMU
# cannot provide is a failed measurement, not a zero.
set -eu

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
cd "$ROOT"

SAMPLES=${NARF_PERCPU_SAMPLES:-30}
ITERATIONS=${NARF_PERCPU_ITERATIONS:-50000}
COHERENCE_EVENT=${NARF_PERCPU_COHERENCE_EVENT:-}
ROOTFS=${NARF_VBLK_IMG:-target/narf-vblk.img}
QEMU_SMP=${NARF_PERCPU_QEMU_SMP:-8}

if [ "$SAMPLES" -lt 30 ]; then
    echo "NARF_PERCPU_SAMPLES must be at least 30 (verification spec §8.3)" >&2
    exit 2
fi
if [ "$ITERATIONS" -le 0 ]; then
    echo "NARF_PERCPU_ITERATIONS must be positive" >&2
    exit 2
fi
if [ "$QEMU_SMP" -le 1 ]; then
    echo "NARF_PERCPU_QEMU_SMP must be greater than one" >&2
    exit 2
fi
if [ ! -e /dev/kvm ]; then
    echo "skip: /dev/kvm is unavailable"
    exit 0
fi
if [ ! -f "$ROOTFS" ]; then
    echo "missing $ROOTFS; build the perf rootfs first:" >&2
    echo "  sudo verification/data/musl-demo/REGEN_perf_rootfs.sh" >&2
    exit 2
fi

revision=$(git rev-parse --short HEAD)
out_dir=target/bench
mkdir -p "$out_dir"
out="$out_dir/percpu-interrupts-${revision}.log"
: >"$out"

events=cache-references,cache-misses,cycles,instructions
if [ -n "$COHERENCE_EVENT" ]; then
    events="$events,$COHERENCE_EVENT"
fi

# `read` is a shell builtin, so this repeatedly opens and consumes the real
# guest procfs file without spawning one `cat` process per iteration.  Its
# generator calls narf_interrupts::snapshot_counters(), which is the exact
# CPU-major collection path being evaluated.
workload="i=0; while [ \"\$i\" -lt $ITERATIONS ]; do while IFS= read -r line; do :; done < /proc/interrupts; i=\$((i + 1)); done"

sample=1
while [ "$sample" -le "$SAMPLES" ]; do
    marker_prefix="PERCPU-INTERRUPTS-SAMPLE-${sample}-"
    marker_suffix="DONE"
    marker="${marker_prefix}${marker_suffix}"
    # `run-interactive` keys off this marker. It is emitted only when guest
    # perf succeeds, and its two quoted pieces prevent serial echo of the
    # typed command from satisfying `--expect` before perf has run.
    command="busybox chroot /mnt perf stat -x, -e $events -- busybox sh -c '$workload' && echo '$marker_prefix'$marker_suffix"
    {
        echo "sample=$sample commit=$revision iterations=$ITERATIONS events=$events"
        XTASK_QEMU_NO_BALLOON=1 \
        NARF_QEMU_MEM_MB=2048 \
        NARF_QEMU_SMP="$QEMU_SMP" \
        NARF_VBLK_IMG="$ROOTFS" \
        XTASK_QEMU_ACCEL=kvm \
        NARF_QEMU_CPU=host \
        XTASK_RI_PROMPT_TIMEOUT_SECS=180 \
        XTASK_RI_ECHO_TIMEOUT_SECS=300 \
        cargo xtask run-interactive --cmd "$command" --expect "$marker"
    } >>"$out" 2>&1
    sample=$((sample + 1))
done

if grep -qi 'not supported\|<not counted>' "$out"; then
    echo "cache PMU event unavailable; raw log retained at $out but is not a valid measurement" >&2
    exit 1
fi

echo "wrote $out"
echo "Compare baseline and candidate under verification/specification/spec.md §8; do not quote this raw collection alone."
