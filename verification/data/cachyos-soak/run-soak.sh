#!/bin/bash
# One QEMU soak of the CachyOS root under a desktop-like load.
#
#   run-soak.sh <name> [mem-mib] [load-seconds]
#
# Boots `cargo xtask cachyos-root-smoke --rw` (CachyOS userspace, systemd as
# PID 1, btrfs root read-write on an emulated NVMe disk, the bare-metal
# command line) with the lockup detector's thresholds shortened, and lets
# narf-soak.service in the image run soak-guest.sh for <load-seconds>. The
# serial console goes to target/soak/<name>/serial.log; soak-report.py turns
# it into a summary.
#
# The image is the cachyos-root-smoke image plus what image-hook.sh adds
# (sshd, tmux, python, git, ripgrep, a `narf` user, this repository's tree
# under /home/narf/src). It is built once; the workload scripts are copied
# onto its ESP before every run, so changing them needs no rebuild.
#
# Host safety: guest disks are regular files under target/, no host block
# device is opened, and every listener and port forward is on 127.0.0.1.
#
#   SOAK_WRAPPER=<cmd>   prefix for the cargo/QEMU command (a build slot)
#   SOAK_KERNEL=<elf>    boot this kernel instead of building the tree
#   SOAK_STALL=<n>       seconds without a pulse from the guest that count as
#                        a stall and end the run (default 90)
#   SOAK_DEADLINE=<n>    seconds after QEMU's first output at which the run is
#                        ended regardless (default: load seconds + 900)
#                        (comparing commits, or soaking while editing)
#   SOAK_SMP=<n>         vCPUs (default 12)
#   SOAK_HEAVY_SECS=<n>  seconds of the threaded file workload alone before
#                        the rest of the desktop load joins (default 420)
#   SOAK_CMDLINE="..."   extra kernel arguments
#   SOAK_ENV="K=V ..."   extra settings for soak-guest.sh
set -euo pipefail

# Everything runs from a function so that bash has parsed the whole file
# before a half-hour run starts; editing the script must not reach a running
# one.
main() {
  ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
  HERE=$ROOT/verification/data/cachyos-soak
  NAME=${1:?usage: run-soak.sh <name> [mem-mib] [load-seconds]}
  MEM_MB=${2:-16384}
  SECS=${3:-1200}
  : "${SOAK_SMP:=12}" "${SOAK_HEAVY_SECS:=420}" "${SOAK_CMDLINE:=}" "${SOAK_ENV:=}" "${SOAK_WRAPPER:=}"
  : "${SOAK_KERNEL:=}" "${SOAK_STALL:=90}"
  WORK=$ROOT/target/soak
  RUN=$WORK/$NAME
  IMAGE=$ROOT/target/narf-cachyos-root.img
  HTTP_PORT=42080 TLS_PORT=42443 UDP_PORT=42053
  SSH_VIRTIO=42222 SSH_E1000=42223 IN_VIRTIO=42301 IN_E1000=42302

  # One run at a time per worktree: every run boots the same scratch disk
  # (target/narf-cachyos-root-rw.img, re-copied at the start of each run) and
  # binds the same localhost ports.
  mkdir -p "$WORK"
  exec 7> "$WORK/.run.lock"
  if ! flock -n 7; then
    echo "run-soak: another soak run is using this worktree; waiting for it" >&2
    flock 7
  fi
  rm -rf "$RUN"
  mkdir -p "$RUN" "$WORK/bin" "$WORK/ssh" "$WORK/tls" "$WORK/tree"
  cd "$ROOT"

  # ── artifacts ───────────────────────────────────────────────────────
  [ -f "$WORK/ssh/id_ed25519" ] ||
    ssh-keygen -q -t ed25519 -N '' -C narf-soak -f "$WORK/ssh/id_ed25519"
  [ -f "$WORK/tls/soak.crt" ] ||
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=narf-soak \
      -keyout "$WORK/tls/soak.key" -out "$WORK/tls/soak.crt" 2> /dev/null
  gcc -O2 -Wall -static -pthread -o "$WORK/bin/soak-native" "$HERE/soak-native.c"
  [ -d "$WORK/tree/narf" ] ||
    git clone -q --no-hardlinks --single-branch "$ROOT" "$WORK/tree/narf"
  if [ ! -f "$IMAGE" ]; then
    CACHYOS_ROOT_SYNC=1 CACHYOS_ROOT_BTRFS_MIB=24576 \
      CACHYOS_ROOT_PACKAGES="openssh tmux python socat git ripgrep ethtool strace" \
      CACHYOS_ROOT_HOOK="$HERE/image-hook.sh" \
      SOAK_PUBKEY="$WORK/ssh/id_ed25519.pub" SOAK_TREE="$WORK/tree/narf" \
      SOAK_NATIVE="$WORK/bin/soak-native" \
      bash "$ROOT/verification/data/cachyos-root/REGEN_cachyos_root_image.sh"
  fi

  # ── the workload, onto the image's ESP (partition 1 starts at 1 MiB) ─
  # Every name is longer than 8.3 on purpose: a short name is stored without
  # its case and comes back upper-cased in the guest.
  {
    echo "SOAK_SECS=$SECS"
    echo "SOAK_HEAVY_SECS=$SOAK_HEAVY_SECS"
    echo "SOAK_HTTP_PORT=$HTTP_PORT"
    echo "SOAK_TLS_PORT=$TLS_PORT"
    echo "SOAK_UDP_PORT=$UDP_PORT"
    for kv in $SOAK_ENV; do echo "$kv"; done
  } > "$RUN/soak-settings.env"
  ESP="$IMAGE@@1048576"
  mmd -D s -i "$ESP" ::/soak 2> /dev/null || true
  mcopy -o -i "$ESP" "$HERE/soak-guest.sh" "$HERE/soak-guest.py" "$WORK/bin/soak-native" \
    "$ROOT/verification/data/host-capture/narf-hang-sampler" "$RUN/soak-settings.env" ::/soak/

  # ── host side ───────────────────────────────────────────────────────
  DEADLINE=${SOAK_DEADLINE:-$((SECS + 900))}
  python3 "$HERE/soak-host.py" --serial-log "$RUN/serial.log" --out-dir "$RUN" \
    --qmp "$RUN/qmp.sock" --key "$WORK/ssh/id_ed25519" --cert "$WORK/tls/soak" \
    --http-port $HTTP_PORT --tls-port $TLS_PORT --udp-port $UDP_PORT \
    --ssh $SSH_VIRTIO --ssh $SSH_E1000 --inbound $IN_VIRTIO --inbound $IN_E1000 \
    --guest-host 10.0.2.2 --guest-host 10.0.3.2 \
    --rip-every 2 --stall "$SOAK_STALL" --deadline "$DEADLINE" > "$RUN/host.log" 2>&1 &
  HOST_PID=$!
  trap 'kill $HOST_PID 2> /dev/null || true' EXIT

  # ── boot ────────────────────────────────────────────────────────────
  # virtio-net stays on QEMU's default 10.0.2.0/24; the e1000 gets its own
  # network so both NICs carry traffic in the same boot.
  export NARF_QEMU_SMP=$SOAK_SMP NARF_QEMU_MEM_MB=$MEM_MB XTASK_QEMU_QMP="$RUN/qmp.sock"
  export XTASK_QEMU_HOSTFWD="tcp:127.0.0.1:$SSH_VIRTIO-:22,hostfwd=tcp:127.0.0.1:$IN_VIRTIO-:5201"
  export XTASK_QEMU_LEGACY_HOSTFWD="tcp:127.0.0.1:$SSH_E1000-:22,hostfwd=tcp:127.0.0.1:$IN_E1000-:5201,net=10.0.3.0/24"
  export XTASK_QEMU_TIMEOUT_SECS=$((DEADLINE + 300))
  CMDLINE=(narf_soak watchdog_thresh=2 sysctl.kernel.hung_task_timeout_secs=20
    btrfs.fatal_errors=panic $SOAK_CMDLINE)
  ARGS=()
  for arg in "${CMDLINE[@]}"; do ARGS+=(--cmdline "$arg"); done
  [ -z "$SOAK_KERNEL" ] || ARGS+=(--prebuilt "$SOAK_KERNEL")
  rc=0
  # The serial console's input: a pipe that stays open and silent (QEMU must
  # not see end-of-file on its stdio serial port).
  exec 8< <(exec sleep $((DEADLINE + 600)))
  QUIET_PID=$!
  # shellcheck disable=SC2086
  $SOAK_WRAPPER timeout -k 15 $((DEADLINE + 240)) cargo xtask cachyos-root-smoke --rw \
    --interactive --serial-log "$RUN/serial.log" "${ARGS[@]}" \
    <&8 > "$RUN/xtask.log" 2>&1 || rc=$?
  kill "$QUIET_PID" 2> /dev/null || true
  echo "run-soak: xtask exited $rc"

  for _ in $(seq 1 30); do
    kill -0 $HOST_PID 2> /dev/null || break
    sleep 1
  done
  cp --reflink=auto "${SOAK_KERNEL:-$ROOT/target/x86_64-unknown-none/release/narf-frame}" \
    "$RUN/narf-frame" 2> /dev/null || true
  python3 "$HERE/soak-report.py" "$RUN" | tee "$RUN/report.txt"
  # The disk, from the host: btrfs check, and the data the guest wrote.
  python3 "$HERE/soak-verify.py" "$RUN" "$ROOT/target/narf-cachyos-root-rw.img" |
    tee "$RUN/verify.txt"
}

main "$@"
