#!/bin/sh
# Build an Alpine rootfs containing stress-ng and perf for the nightly
# `stress-ng-under-KASAN` CI job (.github/workflows/ci.yml).
#
# NARF mounts this ext2 image (QEMU virtio-blk) at /mnt; `chroot_run` chroots
# into it and execs `/bin/busybox sh /probe.sh`, which drives a rotating set of
# stress-ng stressors. Run under `--kasan` so a stray write to a freed slab
# block panics IN the corruptor's frame (see memory/src/kasan.rs).
#
# stress-ng is the right churn tool: its workers fork() in-process (they don't
# re-exec the binary), so they sidestep the busybox same-binary-exec bug
# (memory note narf-execve-same-binary-stale-argv) that breaks shell-driven
# churn. It is a musl-PIE ELF against Alpine's own /lib/ld-musl, which NARF runs.
#
# Fully unprivileged: apk.static installs into a --root dir, mke2fs -d packs it.
#
#   sh verification/data/musl-demo/REGEN_stress_rootfs.sh
#   cargo xtask run-interactive --kasan --cmd chroot_run --expect STRESS-DONE
#
# Output: target/narf-vblk.img (virtio_blk_image_path()). NOT committed.
# Requires: curl, tar, mke2fs (e2fsprogs >= 1.43 for `-d`), network to the
# Alpine CDN. ~40 MiB image.
set -e

ALPINE=v3.21
ARCH=x86_64
CDN=https://dl-cdn.alpinelinux.org/alpine

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
OUT="$ROOT/target/narf-vblk.img"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$ROOT/target"

# apk.static (apk-tools-static) — the unprivileged installer.
echo "fetching apk.static"
IDX=$(curl -fsSL "$CDN/$ALPINE/main/$ARCH/" | grep -oE 'apk-tools-static-[0-9][^"]*\.apk' | head -1)
[ -n "$IDX" ] || { echo "could not find apk-tools-static in the index" >&2; exit 1; }
curl -fsSL -o "$WORK/apk.apk" "$CDN/$ALPINE/main/$ARCH/$IDX"
mkdir -p "$WORK/apk"
tar -xzf "$WORK/apk.apk" -C "$WORK/apk" 2>/dev/null
APK="$WORK/apk/sbin/apk.static"

# Install the base userland, stress-ng, and the unmodified Alpine perf CLI.
RD="$WORK/root"
mkdir -p "$RD/etc/apk"
echo "installing stress-ng + perf + base userland into rootfs"
"$APK" --root "$RD" --arch "$ARCH" --initdb \
    -X "$CDN/$ALPINE/main" -X "$CDN/$ALPINE/community" \
    --allow-untrusted --no-cache \
    add alpine-baselayout busybox musl stress-ng perf

# Alpine stress-ng 0.18 is built without its mremap stressor even though NARF
# implements the syscall. Install the focused in-tree probe so mremap coverage
# is required instead of being silently reported as skipped.
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large \
    "$ROOT/verification/data/musl-demo/mremap_smoke_x86_64.c" \
    -o "$RD/usr/bin/mremap_smoke"

# The workload chroot_run runs. Required MM stressors fail the probe immediately;
# a worker error must never be hidden behind the final completion marker. Each
# stressor is capped so the whole pass fits the CI window even under KASAN's
# outline-check slowdown. `--expect STRESS-DONE` (in the CI job) keys on the
# final marker so run-interactive exits promptly.
cat > "$RD/probe.sh" <<'PROBE'
echo "STRESS-START pid=$$"
DUR="${STRESS_DUR:-6s}"
echo "=== required regression: mmapfork completion ==="
if ! /usr/bin/stress-ng --mmapfork 1 --mmapfork-bytes 4M \
        --mmapfork-ops 1 --timeout 30s --verify --metrics-brief 2>&1; then
  echo "MMAPFORK-FAIL"
  exit 1
fi
echo "MMAPFORK-DONE"

echo "=== required regression: mremap semantics ==="
if ! /usr/bin/mremap_smoke 2>&1; then
  echo "MREMAP-FAIL"
  exit 1
fi
echo "MREMAP-DONE"

# Memory-management correctness matrix. Keep each explicit: this is also the
# checklist consumed when evaluating a memory-sensitive commit. The byte caps
# avoid turning KASAN shadow overhead into an accidental OOM test. One
# stress-ng exec drives the complete sequence: NARF's current exec loader must
# buffer the 4.7 MiB stress-ng ELF contiguously, so re-execing it after every
# stressor would conflate buddy high-order fragmentation with the stressor under
# test. `--sequential` still forks fresh workers for every selected stressor.
echo "=== required sequential MM/process matrix ==="
if ! /usr/bin/stress-ng --sequential 2 \
        --with fork,malloc,vm,mmap,brk,stack,vma,mlock,madvise,fault,shm,pthread,pipe,sock,switch,clone,sigrt,cpu \
        --malloc-bytes 32M --vm-bytes 32M --mmap-bytes 32M \
        --shm-bytes 16M \
        --timeout "$DUR" --abort --verify --stressor-time --metrics-brief 2>&1; then
  echo "STRESS-MATRIX-FAIL"
  exit 1
fi
echo "STRESS-MATRIX-DONE"
echo "=== perf stat: stress-ng cpu ==="
PERF_OUT="$(/usr/bin/perf stat -x, -e 'task-clock,task-clock:u,task-clock:k' -- \
  /usr/bin/stress-ng --cpu 4 --timeout 1s --metrics-brief 2>&1)"
echo "$PERF_OUT"
# Linux defines the privilege filters as no-ops for software CPU clocks. The
# three inherited counts must therefore agree, and a four-worker one-second
# run must retain substantially more than one final scheduler slice.
if ! echo "$PERF_OUT" | awk -F, '
  $3 == "task-clock"   { total = $1 + 0; seen++ }
  $3 == "task-clock:u" { user = $1 + 0; seen++ }
  $3 == "task-clock:k" { kern = $1 + 0; seen++ }
  END {
    if (seen != 3 || total < 500 || user < 500 || kern < 500) exit 1
    min = total; if (user < min) min = user; if (kern < min) min = kern
    max = total; if (user > max) max = user; if (kern > max) max = kern
    if (max - min > max * 0.02) exit 1
  }'
then
  echo "PERF-CLOCK-MISMATCH"
  exit 1
fi
echo "PERF-STRESS-DONE"
echo "STRESS-DONE"
PROBE
chmod +x "$RD/probe.sh"

# Pack into an ext2 image (256 MiB, 1 KiB blocks).
mke2fs -q -F -t ext2 -d "$RD" -b 1024 "$OUT" 262144
echo "built $OUT ($(du -h "$OUT" | cut -f1)); stress-ng+perf present"
