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

for i in {1..180}; do
  proc_state kwin_wayland kwin
  proc_state plasmashell plasma
  proc_state startplasma-way start
  printf 'PLASMA-PROBE %s start=[%s] kwin=[%s] plasma=[%s]\n' \
    "$i" "$start" "$kwin" "$plasma"

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
      exit 0
    fi
  fi
  sleep 2
done

echo 'PLASMA-BLOCKED: kwin_wayland and plasmashell did not both stay alive'
exit 1
