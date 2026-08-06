#!/bin/bash
# Process-level success oracle for the Fedora KDE systemd boot.
set -u

live_pid() {
  local name="$1"
  local -n result="$2"
  local comm_path comm candidate _pid _comm state _rest
  # Use Bash globbing, read, and printf -v only. Command substitution is also
  # deliberately forbidden here: $(...) forks a subshell and waits for its
  # SIGCHLD, which would make the oracle depend on the path it is measuring.
  result=
  for comm_path in /proc/[0-9]*/comm; do
    { IFS= read -r comm < "$comm_path"; } 2>/dev/null || continue
    [ "$comm" = "$name" ] || continue
    candidate=${comm_path#/proc/}
    candidate=${candidate%/comm}
    if { read -r _pid _comm state _rest < "/proc/$candidate/stat"; } 2>/dev/null &&
       [ "$state" != Z ] && [ "$state" != X ]; then
      result=$candidate
      return
    fi
  done
}

proc_state() {
  local name="$1"
  local -n result="$2"
  local pid= stat=
  live_pid "$name" pid
  if [ -z "$pid" ]; then
    result=none
    return
  fi
  { IFS= read -r stat < "/proc/$pid/stat"; } 2>/dev/null || stat=
  if [ -z "$stat" ]; then
    printf -v result 'pid=%s vanished' "$pid"
    return
  fi
  set -- $stat
  printf -v result 'pid=%s state=%s cpu=%s' \
    "$pid" "$3" "$(( ${14} + ${15} ))"
}

live_count() {
  local name="$1"
  local -n result="$2"
  local comm_path comm candidate _pid _comm state _rest
  result=0
  for comm_path in /proc/[0-9]*/comm; do
    { IFS= read -r comm < "$comm_path"; } 2>/dev/null || continue
    [ "$comm" = "$name" ] || continue
    candidate=${comm_path#/proc/}
    candidate=${candidate%/comm}
    if { read -r _pid _comm state _rest < "/proc/$candidate/stat"; } 2>/dev/null &&
       [ "$state" != Z ] && [ "$state" != X ]; then
      (( result += 1 ))
    fi
  done
}

dump_kcminit_waits() {
  local comm_path comm pid field_path field line fdinfo_path fd_path fd_type
  echo 'PLASMA-DIAG kcminit wait snapshot begin'
  for comm_path in /proc/[0-9]*/comm; do
    { IFS= read -r comm < "$comm_path"; } 2>/dev/null || continue
    [ "$comm" = kcminit_startup ] || continue
    pid=${comm_path#/proc/}
    pid=${pid%/comm}
    for field in syscall wchan status; do
      field_path=/proc/$pid/$field
      [ -r "$field_path" ] || continue
      while IFS= read -r line; do
        printf 'PLASMA-DIAG pid=%s %s: %s\n' "$pid" "$field" "$line"
      done < "$field_path"
    done
    for fdinfo_path in /proc/$pid/fdinfo/*; do
      [ -r "$fdinfo_path" ] || continue
      fd=${fdinfo_path##*/}
      while IFS= read -r line; do
        printf 'PLASMA-DIAG pid=%s fdinfo=%s: %s\n' "$pid" "$fd" "$line"
      done < "$fdinfo_path"
      fd_path=/proc/$pid/fd/$fd
      fd_type=other
      [ -p "$fd_path" ] && fd_type=pipe
      [ -S "$fd_path" ] && fd_type=socket
      [ -c "$fd_path" ] && fd_type=char
      [ -b "$fd_path" ] && fd_type=block
      [ -f "$fd_path" ] && fd_type=file
      printf 'PLASMA-DIAG pid=%s fd=%s type=%s\n' "$pid" "$fd" "$fd_type"
    done
  done
  echo 'PLASMA-DIAG kcminit wait snapshot end'
}

# One-shot DRM probe from INSIDE the session, as uid 1000, at the moment
# kwin is actually up.
#
# narf-drm-policy already runs this probe, but it runs at BOOT and as root,
# and both differences matter: kwin opens O_RDWR as uid 1000 while udev may
# still re-apply device ownership afterwards, so a boot-time success says
# nothing about kwin's moment. kwin reports "Failed to open drm device
# /dev/dri/card0" and dies, yet the boot-time probe opens the same node
# fine — so the measurement has to happen HERE, in the same identity and
# the same window, and print errno.
drm_probe_in_session() {
  if [ -x /usr/local/libexec/narf-drm-probe ]; then
    echo "DRMC-SESSION: probing as uid $(id -u) while kwin is up"
    /usr/local/libexec/narf-drm-probe 2>&1 |
      while IFS= read -r l; do printf 'DRMC-SESSION: %s\n' "$l"; done
  else
    echo "DRMC-SESSION: probe binary MISSING"
  fi
  ls -ln /dev/dri/ 2>&1 |
    while IFS= read -r l; do printf 'DRMC-SESSION: ls %s\n' "$l"; done
}
drm_probed=0

# Why are the Plasma units not starting?
#
# They are NOT failing: every one reads "loaded inactive dead start" with a
# Job id, i.e. a QUEUED start job that never runs, and Result=success /
# ExecMainStatus=0 (never attempted). Something upstream is blocking them.
#
# From the image's own unit files the chain is:
#   plasma-workspace-wayland.target Requires+BindsTo plasma-kwin_wayland.service
#   plasma-core.target              After=           plasma-kwin_wayland.service
#   plasma-kwin_wayland.service     BusName=org.kde.KWinWrapper, no Type=
#                                   => systemd infers Type=dbus
# so the whole workspace waits for that ONE name to appear on the session bus.
#
# `list-jobs` names the blocking job directly instead of inferring it from
# dependency files, and ListNames says whether the name is actually there.
# Ask the bus by explicit address: a bare dbus-send inherits whatever the
# environment happens to hold and returned an EMPTY name list in one boot and
# a populated one in another, which is an instrument difference, not a system
# difference.
unit_diag_once() {
  # This probe's own service has no XDG_RUNTIME_DIR, so systemctl --user
  # could not reach the user bus at all and the first version of this
  # diagnostic reported nothing but its own misconfiguration.
  #
  # Which runtime dir is the RIGHT one is itself the open question:
  # narf-plasma.service sets XDG_RUNTIME_DIR=/run/narf-plasma while
  # systemd --user for uid 1000 uses /run/user/1000. If kwin publishes
  # org.kde.KWinWrapper on one bus while the systemd holding the queued jobs
  # watches the other, a Type=dbus unit can never go active — which would
  # explain the stall exactly. So report BOTH, and read kwin's actual
  # environment rather than assuming either.
  export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/1000}"
  echo "UNITBLOCK: probe XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
  for d in /run/user/1000 /run/narf-plasma; do
    printf 'UNITBLOCK: ls %s: ' "$d"
    ls "$d" 2>&1 | tr '\n' ' '
    echo
  done
  kpid=$(pgrep -x kwin_wayland 2>/dev/null | head -1)
  [ -z "$kpid" ] && kpid=$(pgrep -f kwin_wayland 2>/dev/null | head -1)
  echo "UNITBLOCK: kwin pid=${kpid:-none}"
  if [ -n "$kpid" ] && [ -r "/proc/$kpid/environ" ]; then
    tr '\0' '\n' < "/proc/$kpid/environ" 2>/dev/null |
      grep -E '^(XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS|WAYLAND_DISPLAY|XDG_SESSION_TYPE)=' |
      while IFS= read -r l; do printf 'UNITBLOCK: kwin-env %s\n' "$l"; done
  else
    echo "UNITBLOCK: kwin environ unreadable"
  fi
  echo "UNITBLOCK: --- systemctl --user list-jobs ---"
  systemctl --user list-jobs --no-pager 2>&1 |
    while IFS= read -r l; do printf 'UNITBLOCK: %s\n' "$l"; done
  echo "UNITBLOCK: --- plasma-kwin_wayland.service ---"
  systemctl --user show plasma-kwin_wayland.service \
    -p Type -p BusName -p ActiveState -p SubState -p Result -p ExecMainPID 2>&1 |
    while IFS= read -r l; do printf 'UNITBLOCK: %s\n' "$l"; done
  echo "UNITBLOCK: --- names on session bus ---"
  DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus" \
    dbus-send --session --print-reply --dest=org.freedesktop.DBus \
      /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>&1 |
    grep -oE '"[^"]+"' |
    while IFS= read -r l; do printf 'UNITBLOCK: name %s\n' "$l"; done
  echo "UNITBLOCK: done"
}

for i in {1..180}; do
  proc_state kwin_wayland kwin
  proc_state plasmashell plasma
  proc_state startplasma-way start
  proc_state plasma_session session
  proc_state kcminit_startup kcminit
  live_count kcminit_startup kcminit_count
  proc_state kded6 kded
  proc_state ksmserver ksm
  if [ "$drm_probed" = 0 ] && [ "$kwin" != "none" ]; then
    drm_probed=1
    drm_probe_in_session
    unit_diag_once
    # KConfig/QSaveFile atomic writes fail in-session with kwin logging
    # 'Couldn't write ".../kwinrc" . Disk full?'. The image is NOT full and
    # the dirs are uid-1000 owned, so "Disk full?" is KConfig guessing.
    # This names the failing syscall. Runs against the real ext2 /home —
    # the ABI tests for this ran on memfs, which cannot see an ext2-only
    # difference.
    if [ -x /usr/local/libexec/narf-qsf-probe ]; then
      /usr/local/libexec/narf-qsf-probe /home/narf/.config 2>&1 |
        while IFS= read -r l; do printf 'QSFP: %s\n' "$l"; done
    else
      echo "QSFP: probe binary MISSING"
    fi
  fi
  printf 'PLASMA-PROBE %s start=[%s] session=[%s] kwin=[%s] kcminit=[%s count=%s] kded=[%s] ksm=[%s] plasma=[%s]\n' \
    "$i" "$start" "$session" "$kwin" "$kcminit" "$kcminit_count" "$kded" "$ksm" "$plasma"

  # One delayed, cold-path snapshot is enough to identify the descriptor set
  # behind a stable kcminit gate without tracing every poll or perturbing the
  # scheduler's hot syscall path.
  if [ "$i" -eq 40 ] && [ "$kcminit_count" -gt 0 ]; then
    dump_kcminit_waits
  fi

  live_pid kwin_wayland kwin_pid
  live_pid plasmashell plasma_pid
  if [ -n "$kwin_pid" ] && [ -n "$plasma_pid" ]; then
    # Do not pass on a transient exec. Both processes must survive another
    # scheduler interval. Require the SAME non-zombie PIDs at both samples;
    # a missed SIGCHLD must not let a zombie or restart loop satisfy the gate.
    sleep 10
    live_pid kwin_wayland kwin_pid_after
    live_pid plasmashell plasma_pid_after
    if [ "$kwin_pid_after" = "$kwin_pid" ] &&
       [ "$plasma_pid_after" = "$plasma_pid" ]; then
      echo 'PLASMA-READY: kwin_wayland and plasmashell survived 10s'
      # Liveness is not a drawn desktop. KWin presents its startup frames
      # and then idles because no client window is ever mapped, so the
      # interesting interval starts exactly where this oneshot used to
      # exit. Hand the sampling to a background writer and let the start
      # job complete, so graphical.target still gates on PLASMA-READY.
      #
      # A climbing CPU counter means the process is making progress and is
      # merely slow; a flat one means it is parked. That distinction is
      # what decides whether the shell needs more time or a lost wakeup.
      (
        for j in {1..600}; do
          proc_state kwin_wayland kwin
          proc_state plasmashell plasma
          proc_state foot foot
          printf 'PLASMA-WATCH %s kwin=[%s] plasma=[%s] foot=[%s]\n' \
            "$j" "$kwin" "$plasma" "$foot"
          sleep 5
        done
      ) &
      exit 0
    fi
  fi
  sleep 2
done

echo 'PLASMA-BLOCKED: kwin_wayland and plasmashell did not both stay alive'
exit 1
