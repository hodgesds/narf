#!/bin/bash
# run_ci_locally_parallel.sh — PARALLEL local CI gate (correctness, not perf).
#
# ./run_ci_locally.sh remains the REFERENCE gate; this script runs the same
# job set split across lanes to cut wall-clock time. CPU contention between
# lanes is acceptable — these are correctness gates, not perf runs.
#
# ── Lane layout ──────────────────────────────────────────────────────────────
#   serial preamble (main repo): cargo fmt --check → cargo xtask host-test
#     (fast, and everything depends on fmt; in --affected mode the plan is
#      computed first, exactly like the serial gate)
#   lane A  x86_64 pipeline : clippy (boot-smoke,cgroup-all) → clippy
#                             (kernel-test,cgroup-all) → xtask test → boot-smoke
#   lane B  aarch64 pipeline: same four jobs for aarch64 (TCG guest is
#                             CPU-hungry — it is paired with the light lanes)
#   lane C  smokes          : musl-demo → net-smoke → redis-smoke
#                             (the only lane that binds host TCP ports)
#   lane D  feature matrix  : the 4 narf-userspace + 5 narf-frame combos
#
# ── Per-lane isolation (READ THIS — it is not CARGO_TARGET_DIR) ─────────────
# xtask HARDCODES <repo>/target for its artifacts: cargo_build() returns
# root.join("target")/<triple>/release (build/xtask/src/main.rs:2545) and the
# QEMU disk images (narf-nvme.img, narf-vblk.img, qemu-virt.dtb, ISO staging,
# firmware) all live under root/target too. Setting CARGO_TARGET_DIR makes
# cargo build elsewhere while xtask BOOTS THE STALE KERNEL from target/ —
# silently wrong. So instead each lane gets a PRIVATE REPO COPY under
# $NARF_CI_LANES_DIR (default /data/narf-ci-lanes/<lane>), synced from the
# main tree with rsync/cp --reflink=auto (near-free on btrfs), each with its
# own private target/. This also gives every QEMU its own private disk
# images (reflink copies by construction), avoiding the documented NVMe
# image write-lock collision between concurrent QEMU instances, and keeps
# the lanes from clobbering the single target/x86_64-unknown-none/release/
# narf-frame path with different feature builds.
#
# DISK COST: source+.git ≈ 2 GB/lane (≈0 extra on btrfs reflink); each lane's
# target/ grows to roughly 20–60 GB on a full matrix. Lane dirs persist
# across runs for incremental rebuilds; delete them to reclaim space.
# --seed-target reflinks the main repo's target/ into a lane on first sync
# (fast warm start) — DO NOT use it while another gate is writing target/.
#
# ── Ports (known gotcha) ────────────────────────────────────────────────────
# net-smoke binds host 127.0.0.1:17777 and redis-smoke 127.0.0.1:16379 —
# both HARDCODED in xtask (no env override), so they cannot be remapped per
# lane. Both live in lane C and run sequentially, so this script never
# collides with itself; before each, the lane waits (up to --port-wait-secs,
# default 900) for the port to be free. A stale QEMU squatting on 16379 is a
# known way to poison redis runs — the wait message names the port so you can
# `fuser -k 16379/tcp` a zombie.
#
# ── Timeout hardening / retry ───────────────────────────────────────────────
# Lanes contend for CPU, so every wall-clock knob the serial gate sets is
# scaled 3x (XTASK_RI_PROMPT/ECHO_TIMEOUT_SECS 900→2700, XTASK_QEMU_TIMEOUT
# _SECS 2400→7200, XTASK_BOOT_SMOKE_TIMEOUT_SECS 1200→3600). After all lanes
# finish, any FAILED job whose log shows a timeout signature
# (grep -iE 'timeout|did not see|prompt') is re-run once, serially, before
# the final verdict — contention-induced timeouts must not go red.
#
# ── Orchestration ───────────────────────────────────────────────────────────
# Plain bash background jobs + wait (zero deps; GNU parallel deliberately not
# used). Fail-fast is OFF by default (all failures are collected);
# --fail-fast stops STARTING new jobs after the first failure (jobs already
# running finish). Logs: /tmp/ci-lanes/<lane>.log (lane progress) and
# /tmp/ci-lanes/<lane>/<job>.log (full per-job output), plus a combined
# verdict table at the end.
#
# ── Coverage notes ──────────────────────────────────────────────────────────
# Mirrors run_ci_locally.sh's full job set 1:1, PLUS redis-smoke (agreed
# addition; the serial gate does not run it — CI only exercises it in the
# nightly task87 job). CI-only jobs NOT run here (also absent from the serial
# reference gate): iso-boot, the aarch64 uefi-loader tests/clippy, the
# aarch64 virtio-mmio-populated kernel-test pass, and the nightly
# non-blocking task87-repro / stress-ng-kasan diagnostics.
# --affected/--base are preserved: the same `cargo xtask affected` plan the
# serial gate uses gates jobs/lanes here (redis-smoke follows the net-smoke
# gate). Resource assumptions: ~16 cores / 60 GB RAM / KVM at /dev/kvm.
#
# usage: ./run_ci_locally_parallel.sh [--affected] [--base=<git-ref>]
#                                     [--dry-run] [--fail-fast]
#                                     [--seed-target] [--port-wait-secs=N]

set -eu

SRC="$(cd "$(dirname "$0")" && pwd)"
LANES_DIR="${NARF_CI_LANES_DIR:-/data/narf-ci-lanes}"
RESULTS_DIR="${NARF_CI_RESULTS_DIR:-/tmp/ci-lanes}"

AFFECTED=0
BASE="origin/main"
DRY_RUN=0
FAIL_FAST=0
SEED_TARGET=0
PORT_WAIT_SECS=900
for arg in "$@"; do
  case "$arg" in
    --affected) AFFECTED=1 ;;
    --base=*) BASE="${arg#--base=}" ;;
    --dry-run) DRY_RUN=1 ;;
    --fail-fast) FAIL_FAST=1 ;;
    --seed-target) SEED_TARGET=1 ;;
    --port-wait-secs=*) PORT_WAIT_SECS="${arg#--port-wait-secs=}" ;;
    -h|--help)
      sed -n '2,90p' "$0" | grep -E '^# ?' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

case "$LANES_DIR" in
  "$SRC"|"$SRC"/*) echo "NARF_CI_LANES_DIR must be OUTSIDE the repo (got $LANES_DIR)" >&2; exit 2 ;;
esac

# ── affected plan (identical to run_ci_locally.sh) ──────────────────────────
FULL=true
RUN_CLIPPY=true
RUN_BOOT_SMOKE=true
RUN_MUSL=true
RUN_NET=true
RUN_KERNEL_TEST=true
RUN_FEATURE_MATRIX=true
ARCHES='["x86_64","aarch64"]'
SUBS=""

if [ "$AFFECTED" = 1 ]; then
  if [ "$DRY_RUN" = 1 ]; then
    echo "--dry-run: skipping \`cargo xtask affected\` (it builds/runs xtask);"
    echo "  at run time the plan would come from:"
    echo "    cargo xtask affected --format github --event pull_request --base $BASE"
    echo "  showing the FULL-run plan below."
  else
    echo "Computing affected jobs vs $BASE ..."
    PLAN="$(cd "$SRC" && cargo xtask affected --format github --event pull_request --base "$BASE")"
    echo "$PLAN"
    get() { printf '%s\n' "$PLAN" | grep "^$1=" | cut -d= -f2-; }
    FULL="$(get full)"
    RUN_CLIPPY="$(get run_clippy)"
    RUN_BOOT_SMOKE="$(get run_boot_smoke)"
    RUN_MUSL="$(get run_musl_demo)"
    RUN_NET="$(get run_net_smoke)"
    RUN_KERNEL_TEST="$(get run_kernel_test)"
    RUN_FEATURE_MATRIX="$(get run_feature_matrix)"
    ARCHES="$(get clippy_arches)"
    SUBS="$(get subsystems)"
  fi
fi

should() { [ "$FULL" = "true" ] || [ "$1" = "true" ]; }
arch_on() { printf '%s' "$ARCHES" | grep -q "\"$1\""; }

# ── shared helpers (export -f: job commands run via bash -c) ────────────────
# A "free" port refuses the connect; a listener (stale QEMU, the serial gate's
# own smoke) accepts it. Pure-bash /dev/tcp probe — no nc/ss dependency.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_port_free() {
  local port="$1" waited=0
  while port_busy "$port"; do
    if [ "$waited" -ge "$PORT_WAIT_SECS" ]; then
      echo "port $port still busy after ${PORT_WAIT_SECS}s — stale QEMU or a" \
           "concurrent gate holds it (try: fuser -k $port/tcp)" >&2
      return 1
    fi
    echo "waiting for host port $port to free (stale QEMU / concurrent run?)..."
    sleep 15; waited=$((waited + 15))
  done
}
export -f port_busy wait_port_free
export PORT_WAIT_SECS

# Env every job runs under — mirrors the serial gate's globals. Job-specific
# timeout knobs (already 3x-scaled) are appended per job below.
COMMON_ENV='export CARGO_TERM_COLOR=always RUSTFLAGS="" XTASK_QEMU_NO_BALLOON=1 NARF_QEMU_MEM_MB=2048;'

KFLAGS="-Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128"

# kernel-test subsystem filter (identical condition to the serial gate).
KT_SUBS=""
if [ -n "$SUBS" ] && [ "$FULL" != "true" ]; then
  KT_SUBS=" --subsystem $SUBS"
fi

# ── job table ───────────────────────────────────────────────────────────────
JOB_LANE=(); JOB_NAME=(); JOB_CMD=()
add_job() { # add_job <lane> <name> <cmd...>
  local lane="$1" name="$2"; shift 2
  JOB_LANE+=("$lane"); JOB_NAME+=("$name")
  JOB_CMD+=("set -eu; $COMMON_ENV cd '$LANES_DIR/$lane'; set -x; $*")
}

# lane A — x86_64 pipeline (clippy → xtask test builds+runs → boot-smoke)
if should "$RUN_CLIPPY"; then
  add_job A clippy-x86_64 \
    "cargo clippy -p narf-frame --target x86_64-unknown-none $KFLAGS --features boot-smoke,cgroup-all -- -D warnings"
  add_job A clippy-x86_64-kernel-test \
    "cargo clippy -p narf-frame --target x86_64-unknown-none $KFLAGS --features kernel-test,cgroup-all -- -D warnings"
fi
if should "$RUN_KERNEL_TEST"; then
  add_job A kernel-test-x86_64 \
    "export XTASK_QEMU_TIMEOUT_SECS=7200 XTASK_BOOT_SMOKE_TIMEOUT_SECS=3600; cargo xtask test --arch=x86_64 --features cgroup-all,container$KT_SUBS"
fi
if should "$RUN_BOOT_SMOKE"; then
  add_job A boot-smoke-x86_64 "cargo xtask boot-smoke --arch=x86_64"
fi

# lane B — aarch64 pipeline (TCG guest; runs beside the lighter lanes)
if arch_on aarch64; then
  if should "$RUN_CLIPPY"; then
    add_job B clippy-aarch64 \
      "cargo clippy -p narf-frame --target aarch64-unknown-none $KFLAGS --features boot-smoke,cgroup-all -- -D warnings"
    add_job B clippy-aarch64-kernel-test \
      "cargo clippy -p narf-frame --target aarch64-unknown-none $KFLAGS --features kernel-test,cgroup-all -- -D warnings"
  fi
  if should "$RUN_KERNEL_TEST"; then
    add_job B kernel-test-aarch64 \
      "export XTASK_QEMU_TIMEOUT_SECS=7200 XTASK_BOOT_SMOKE_TIMEOUT_SECS=3600; cargo xtask test --arch=aarch64 --features cgroup-all,container$KT_SUBS"
  fi
  if should "$RUN_BOOT_SMOKE"; then
    add_job B boot-smoke-aarch64 "cargo xtask boot-smoke --arch=aarch64"
  fi
fi

# lane C — QEMU smokes (sole owner of the hardcoded host ports)
if should "$RUN_MUSL"; then
  add_job C musl-demo \
    "export XTASK_RI_PROMPT_TIMEOUT_SECS=2700 XTASK_RI_ECHO_TIMEOUT_SECS=2700; cargo xtask musl-demo --arch=x86_64"
fi
if should "$RUN_NET"; then
  add_job C net-smoke \
    "export XTASK_RI_PROMPT_TIMEOUT_SECS=2700; wait_port_free 17777; cargo xtask net-smoke --arch=x86_64"
  # Not in the serial reference gate (CI: nightly task87 job only); agreed
  # addition here. Gated with net-smoke in --affected mode.
  add_job C redis-smoke \
    "export XTASK_RI_PROMPT_TIMEOUT_SECS=2700; wait_port_free 16379; cargo xtask redis-smoke --arch=x86_64"
fi

# lane D — feature matrix (keep identical to run_ci_locally.sh / ci.yml)
if should "$RUN_FEATURE_MATRIX"; then
  add_job D feature-matrix "
    cargo check -p narf-userspace --no-default-features
    cargo check -p narf-userspace --no-default-features --features 'container'
    cargo check -p narf-userspace --no-default-features --features 'cgroup'
    cargo check -p narf-userspace --no-default-features --features 'container,cgroup'
    for f in 'container' 'cgroup' 'container,cgroup' 'cgroup-all' 'container,cgroup-all'; do
      cargo check -p narf-frame --target x86_64-unknown-none $KFLAGS --features \"\$f\"
    done"
fi

# distinct lanes actually holding jobs, in stable order
LANES=""
for lane in A B C D; do
  for ((i = 0; i < ${#JOB_NAME[@]}; i++)); do
    if [ "${JOB_LANE[i]}" = "$lane" ]; then LANES="$LANES $lane"; break; fi
  done
done

# ── dry-run: print the plan and every exact command, execute nothing ────────
if [ "$DRY_RUN" = 1 ]; then
  echo "=== DRY RUN — no builds, no QEMU, no filesystem changes ==="
  echo "main repo   : $SRC"
  echo "lane roots  : $LANES_DIR/<lane>  (rsync/cp --reflink sync, private target/)"
  echo "logs        : $RESULTS_DIR/<lane>.log + $RESULTS_DIR/<lane>/<job>.log"
  echo "fail-fast   : $FAIL_FAST   seed-target: $SEED_TARGET   port-wait: ${PORT_WAIT_SECS}s"
  echo
  echo "--- serial preamble (in $SRC) ---"
  echo "  cargo fmt --all -- --check"
  echo "  cargo xtask host-test"
  echo
  for lane in $LANES; do
    echo "--- lane $lane (root: $LANES_DIR/$lane) ---"
    echo "  sync: rsync -a --delete --exclude=/target --exclude='/target-*' '$SRC/' '$LANES_DIR/$lane/'"
    for ((i = 0; i < ${#JOB_NAME[@]}; i++)); do
      [ "${JOB_LANE[i]}" = "$lane" ] || continue
      echo "  job ${JOB_NAME[i]}:"
      printf '%s\n' "${JOB_CMD[i]}" | sed 's/^/    | /'
    done
    echo
  done
  echo "then: wait for all lanes; retry (serially, once) any FAILED job whose"
  echo "log matches -iE 'timeout|did not see|prompt'; print verdict table."
  exit 0
fi

# ── serial preamble: fmt + host tests in the main repo ──────────────────────
echo "Running fmt"
(cd "$SRC" && cargo fmt --all -- --check)
echo "Running host tests"
(cd "$SRC" && cargo xtask host-test)

# ── lane workspace sync ─────────────────────────────────────────────────────
sync_lane() {
  local lane="$1" dst="$LANES_DIR/$lane"
  mkdir -p "$dst"
  if command -v rsync >/dev/null 2>&1; then
    # --delete keeps the copy honest; the excluded target*/ dirs are
    # protected from deletion, so lane builds stay incremental across runs.
    rsync -a --delete --exclude=/target --exclude='/target-*' "$SRC/" "$dst/"
  else
    local entry base
    for entry in "$dst"/* "$dst"/.[!.]* "$dst"/..?*; do
      [ -e "$entry" ] || continue
      base="$(basename "$entry")"
      case "$base" in target|target-*) ;; *) rm -rf "$entry" ;; esac
    done
    for entry in "$SRC"/* "$SRC"/.[!.]* "$SRC"/..?*; do
      [ -e "$entry" ] || continue
      base="$(basename "$entry")"
      case "$base" in target|target-*) ;; *) cp -a --reflink=auto "$entry" "$dst/" ;; esac
    done
  fi
  if [ "$SEED_TARGET" = 1 ] && [ ! -e "$dst/target" ] && [ -d "$SRC/target" ]; then
    echo "[seed] reflinking $SRC/target -> $dst/target (must not race a writer!)"
    cp -a --reflink=auto "$SRC/target" "$dst/target"
  fi
}

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/abort
for lane in $LANES; do
  mkdir -p "$RESULTS_DIR/$lane"
  rm -f "$RESULTS_DIR/$lane.log" "$RESULTS_DIR/$lane"/*.log "$RESULTS_DIR/$lane"/*.status
  echo "Syncing lane $lane workspace -> $LANES_DIR/$lane"
  sync_lane "$lane"
done

# ── lane execution ──────────────────────────────────────────────────────────
run_job() { # run_job <idx> ; echoes progress, writes log + status
  local i="$1" lane="${JOB_LANE[$1]}" name="${JOB_NAME[$1]}"
  local log="$RESULTS_DIR/$lane/$name.log" st="$RESULTS_DIR/$lane/$name.status"
  local t0 s dt
  t0=$(date +%s)
  echo "[$(date +%H:%M:%S)] [$lane] START $name"
  if bash -c "${JOB_CMD[i]}" >"$log" 2>&1; then s=pass; else s=fail; fi
  dt=$(( $(date +%s) - t0 ))
  echo "$s $dt" >"$st"
  echo "[$(date +%H:%M:%S)] [$lane] ${s^^} $name (${dt}s) log=$log"
  if [ "$s" = fail ] && [ "$FAIL_FAST" = 1 ]; then touch "$RESULTS_DIR/abort"; fi
}

run_lane() {
  local lane="$1" i
  for ((i = 0; i < ${#JOB_NAME[@]}; i++)); do
    [ "${JOB_LANE[i]}" = "$lane" ] || continue
    if [ -e "$RESULTS_DIR/abort" ]; then
      echo "skipped-abort 0" >"$RESULTS_DIR/$lane/${JOB_NAME[i]}.status"
      echo "[$lane] SKIP ${JOB_NAME[i]} (fail-fast abort)"
      continue
    fi
    run_job "$i"
  done
}

trap 'echo "interrupted — killing lanes"; kill $(jobs -p) 2>/dev/null || true; exit 130' INT TERM

LANE_PIDS=""
for lane in $LANES; do
  run_lane "$lane" > >(tee -a "$RESULTS_DIR/$lane.log") 2>&1 &
  LANE_PIDS="$LANE_PIDS $!"
done

for pid in $LANE_PIDS; do
  wait "$pid" || true # per-job status files carry the verdict
done
trap - INT TERM

# ── retry pass: contention-induced timeouts get one serial re-run ───────────
for ((i = 0; i < ${#JOB_NAME[@]}; i++)); do
  lane="${JOB_LANE[i]}"; name="${JOB_NAME[i]}"
  st="$RESULTS_DIR/$lane/$name.status"; log="$RESULTS_DIR/$lane/$name.log"
  [ -f "$st" ] || continue
  read -r status _ <"$st"
  [ "$status" = fail ] || continue
  if grep -qiE 'timeout|did not see|prompt' "$log"; then
    echo "RETRY [$lane] $name — failure log shows a timeout signature; re-running serially"
    t0=$(date +%s)
    if bash -c "${JOB_CMD[i]}" >"$log.retry" 2>&1; then s=pass-retry; else s=fail-retry; fi
    echo "$s $(( $(date +%s) - t0 ))" >"$st"
    echo "RETRY [$lane] $name -> $s (log=$log.retry)"
  fi
done

# ── verdict ─────────────────────────────────────────────────────────────────
echo
echo "── combined verdict ────────────────────────────────────────────────"
printf '%-4s %-28s %-14s %8s  %s\n' LANE JOB STATUS SECS LOG
OVERALL=0
for ((i = 0; i < ${#JOB_NAME[@]}; i++)); do
  lane="${JOB_LANE[i]}"; name="${JOB_NAME[i]}"
  st="$RESULTS_DIR/$lane/$name.status"
  if [ -f "$st" ]; then read -r status secs <"$st"; else status=not-run; secs=0; fi
  case "$status" in
    pass|pass-retry) ;;
    *) OVERALL=1 ;;
  esac
  printf '%-4s %-28s %-14s %8s  %s\n' "$lane" "$name" "$status" "$secs" "$RESULTS_DIR/$lane/$name.log"
done
echo "────────────────────────────────────────────────────────────────────"
if [ "$OVERALL" = 0 ]; then
  echo "ALL CI TESTS PASSED (parallel gate)"
else
  echo "CI GATE FAILED — see the logs above" >&2
fi
exit "$OVERALL"
