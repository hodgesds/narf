#!/bin/bash
# ── Session bus: a real `systemd --user` manager, not a private bus ───
#
# This script is the session entry point (narf-plasma.service ExecStart).
# It used to be wrapped in `dbus-run-session`, which creates a bare private
# bus with NO user manager behind it. `org.freedesktop.systemd1` IS the user
# manager's own bus name, so without it Plasma 6's startup path cannot work:
# its components ship as systemd USER units (plasma-kwin_wayland.service,
# plasma-plasmashell.service, plasma-kactivitymanagerd.service, ...) driven
# through plasma-workspace.target. The private bus is exactly why the log
# reported `org.kde.Startup` (x35) and `org.freedesktop.systemd1` (x11) as
# "not provided by any .service files", and why org.kde.ActivityManager and
# org.freedesktop.Notifications had only D-Bus activation left and timed out
# at 120 s each.
#
# user@$UID.service pulls in user-runtime-dir@$UID.service (which creates
# /run/user/$UID) and starts `systemd --user`, whose dbus.socket publishes
# the session bus at /run/user/$UID/bus.
if [ -z "${NARF_USERBUS_TRIED:-}" ]; then
  export NARF_USERBUS_TRIED=1
  narf_uid=$(id -u)
  narf_user_bus="/run/user/$narf_uid/bus"
  echo "FED-USERBUS: starting user@$narf_uid.service"
  systemctl start "user@$narf_uid.service" 2>&1 | sed 's/^/FED-USERBUS: /' || true
  narf_bus_ready=0
  for i in $(seq 1 60); do
    # The socket FILE existing is NOT the readiness condition — systemd
    # creates the listener up front and activates dbus on first connect, so
    # a broken activation handoff leaves a socket that exists and answers
    # nothing. Testing -S alone declared the bus ready, which suppressed the
    # dbus-run-session fallback and stalled the whole session with no
    # diagnosis. Require an actual round-trip.
    if [ -S "$narf_user_bus" ] &&
       DBUS_SESSION_BUS_ADDRESS="unix:path=$narf_user_bus" \
       timeout 5 dbus-send --session --print-reply \
         --dest=org.freedesktop.DBus /org/freedesktop/DBus \
         org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
      narf_bus_ready=1
      break
    fi
    if [ $((i % 15)) -eq 0 ]; then
      echo "FED-USERBUS: waiting for $narf_user_bus ($i/60)"
      systemctl status "user@$narf_uid.service" --no-pager 2>&1 \
        | sed 's/^/FED-USERBUS: /' | head -10
    fi
    sleep 1
  done
  # Diagnostics run UNCONDITIONALLY, and after the exports below — two traps
  # this block already fell into:
  #   * inside the success branch they only fire when the bus WORKS, which is
  #     the one case needing no diagnosis;
  #   * before the exports, `systemctl --user` has no runtime dir and
  #     dbus-send never uses the bus path at all — it tries to autolaunch and
  #     dies on $DISPLAY, which reads as a bus failure but only measures the
  #     missing environment.
  # XDG_RUNTIME_DIR must agree with where the manager published its socket,
  # or the session and the manager look at different runtime dirs.
  export XDG_RUNTIME_DIR="/run/user/$narf_uid"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$narf_user_bus"
  echo "FED-BUSDIAG: bus_ready=$narf_bus_ready"
  echo "FED-BUSDIAG: --- dbus.socket / dbus.service ---"
  systemctl --user status dbus.socket dbus.service --no-pager -l 2>&1 \
    | sed 's/^/FED-BUSDIAG: /' | head -40
  echo "FED-BUSDIAG: --- failed units ---"
  systemctl --user list-units --failed --no-pager --no-legend 2>&1 \
    | sed 's/^/FED-BUSDIAG: /' | head -20
  echo "FED-BUSDIAG: --- is the socket answering? ---"
  # Capture the rc BEFORE any pipe — a pipeline's $? is the last stage's
  # (sed's), which is always 0 and would report a hung bus as healthy.
  narf_busout=$(timeout 10 dbus-send --session --print-reply \
    --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.ListNames 2>&1)
  narf_busrc=$?
  echo "FED-BUSDIAG: dbus-send rc=$narf_busrc (124=timeout/hung)"
  printf '%s\n' "$narf_busout" | sed 's/^/FED-BUSDIAG: /' | head -6
  echo "FED-BUSDIAG: --- socket + dbus processes ---"
  ls -l "$narf_user_bus" 2>&1 | sed 's/^/FED-BUSDIAG: /'
  ps -eo pid,user,comm 2>/dev/null | grep -iE "dbus|systemd" \
    | sed 's/^/FED-BUSDIAG: /' | head -15

  if [ "$narf_bus_ready" -eq 1 ]; then
    echo "FED-USERBUS: user manager up; session bus at $narf_user_bus"
    # The manager inherits nothing from us; push the graphical-session
    # variables in, as a display manager does.
    systemctl --user import-environment \
      XDG_RUNTIME_DIR XDG_SESSION_TYPE XDG_CURRENT_DESKTOP PATH LANG \
      QT_QPA_PLATFORM KWIN_DRM_NO_AMS KWIN_DRM_DEVICES KWIN_COMPOSE \
      LIBGL_ALWAYS_SOFTWARE GALLIUM_DRIVER 2>&1 \
      | sed 's/^/FED-USERBUS: /' || true
    # Plasma consults startkderc to decide whether to use its systemd units.
    if [ -n "${XDG_CONFIG_HOME:-}" ] || [ -n "${HOME:-}" ]; then
      narf_cfg="${XDG_CONFIG_HOME:-$HOME/.config}"
      mkdir -p "$narf_cfg" 2>/dev/null || true
      printf '[General]\nsystemdBoot=true\n' > "$narf_cfg/startkderc" 2>/dev/null || true
    fi
  else
    # Say so LOUDLY and name the failures that follow. A silent fallback
    # reproduces the same 120 s timeouts with nothing explaining why.
    echo "FED-USERBUS-FALLBACK: user@$narf_uid.service never published $narf_user_bus"
    echo "FED-USERBUS-FALLBACK: re-execing under a private dbus-run-session bus."
    echo "FED-USERBUS-FALLBACK: expect org.kde.Startup / org.freedesktop.systemd1"
    echo "FED-USERBUS-FALLBACK: ServiceUnknown and 120s activation timeouts."
    exec /usr/bin/dbus-run-session -- "$0" "$@"
  fi
fi

# Keep this trace at the D-Bus protocol boundary: KWin's Wayland wrapper does
# not claim org.kde.KWinWrapper until every launch-environment update replies.
# The serial/reply_serial pairs identify the exact request holding that gate.
echo "PLASMA-DBUS-MONITOR starting"
/usr/bin/dbus-monitor --session --monitor \
  "type='method_call',interface='org.kde.Startup',member='updateLaunchEnv'" \
  "type='method_call',interface='org.freedesktop.DBus',member='UpdateActivationEnvironment'" \
  "type='method_call',interface='org.freedesktop.DBus',member='StartServiceByName'" \
  "type='method_call',interface='org.freedesktop.DBus',member='AddMatch'" \
  "type='method_call',interface='org.freedesktop.DBus',member='RemoveMatch'" \
  "type='method_call',interface='org.freedesktop.systemd1.Manager',member='SetEnvironment'" \
  "type='method_return'" \
  "type='error'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.KWinWrapper'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.kcminit'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.kded6'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.ksmserver'" &

# Test the GLib D-Bus delivery layer independently of Qt's
# QDBusServiceWatcher. The external bus monitor proves that the daemon emits
# NameOwnerChanged; this waiter proves that a separate GLib client can install
# a match, park its main context, consume the same ownership transition, and
# return. Keep it unbounded so a missing delivery remains visible for the
# lifetime of the acceptance run.
(
  echo "PLASMA-GDBUS-WAIT kded start"
  /usr/bin/gdbus wait --session org.kde.kded6
  status=$?
  if [ "$status" -eq 0 ]; then
    echo "PLASMA-GDBUS-WAIT kded observed"
  else
    echo "PLASMA-GDBUS-WAIT kded failed status=$status"
  fi
) &

# Resume the classic-session sequence after the one proven StartServiceJob
# callback gate. The supervisor uses the same focused Qt watcher exercised by
# the preceding replay and logs each process/name boundary.
/usr/local/libexec/narf-plasma-classic-supervisor &

# Once the user bus works, Plasma's components run as systemd USER UNITS,
# so their stderr goes to the journal and NOTHING about a crash reaches the
# serial console — the same wall that hid the earlier 219/EXIT_CGROUP
# failures. Snapshot the user manager's own view periodically; `systemctl
# --user` naming an exit code is what cracked the previous two bugs.
# Backgrounded and repeated because the interesting window (kded starting,
# dying, being restarted) is tens of seconds after startplasma.
(
  for delay in 20 45 90; do
    /usr/bin/sleep "$delay"
    echo "PLASMA-UNITDIAG[t+${delay}]: --- failed user units ---"
    systemctl --user list-units --failed --no-pager --no-legend 2>&1 \
      | sed "s/^/PLASMA-UNITDIAG[t+${delay}]: /" | head -20
    echo "PLASMA-UNITDIAG[t+${delay}]: --- plasma units ---"
    systemctl --user list-units --no-pager --no-legend \
      'plasma-*' 'app-*' 2>&1 \
      | sed "s/^/PLASMA-UNITDIAG[t+${delay}]: /" | head -25
    # kded specifically: it starts, exits, and gets restarted in a loop.
    # Result= / status= here names WHY, which the console never shows.
    systemctl --user status plasma-kded6.service --no-pager -l 2>&1 \
      | sed "s/^/PLASMA-UNITDIAG[t+${delay}]: /" | head -25
    echo "PLASMA-UNITDIAG[t+${delay}]: --- recent user journal ---"
    journalctl --user -n 40 --no-pager -p warning 2>&1 \
      | sed "s/^/PLASMA-UNITDIAG[t+${delay}]: /" | head -45
  done
) &

# startplasma makes only SetEnvironment calls to org.freedesktop.systemd1 and
# never StartUnit, so it takes the CLASSIC path even though startkderc says
# systemdBoot=true, the units are all installed, and the user bus works. Its
# own qCDebug categories are off, so the decision is not recoverable from the
# console.
#
# Drive the target ourselves and see whether the units come up. This separates
# two very different questions: "can these units run on NARF at all?" from
# "why does startplasma decline to start them?" — and if they do run, the
# session gains plasmashell, which is the whole point. Units started here are
# owned by the user manager, so they outlive this subshell even though it dies
# with the session's cgroup.
(
  /usr/bin/sleep 15
  # plasma-workspace.target and plasma-core.target are RefuseManualStart=yes
  # (dependency-only), and plasma-workspace-wayland.target Requires
  # plasma-kwin_wayland.service — which would start a SECOND kwin next to the
  # one startplasma already launched on the classic path. Start the leaf
  # services instead: plasmashell is the actual missing piece, and it slots
  # into the existing compositor.
  #
  # plasmashell is Type=dbus on org.kde.plasmashell, so `start` blocks until
  # it claims the name — a timeout here is itself the answer.
  # The user manager has XDG_RUNTIME_DIR / QT_QPA_PLATFORM / XDG_SESSION_TYPE
  # but NOT WAYLAND_DISPLAY, so every Plasma unit starts blind and a Type=dbus
  # unit like plasmashell hangs forever waiting to claim its name. Nothing
  # publishes it: `import-environment` runs before kwin exists, and on the
  # classic path startplasma has no reason to SetEnvironment it.
  #
  # Discover the socket kwin actually created rather than assuming wayland-0 —
  # kwin picks the first free name, so a stale socket shifts it to wayland-1.
  # POLL, don't snapshot. kwin does not appear until ~40-60 s into the
  # session; a single early check reported "no wayland socket" when the
  # truth was "not yet", which is indistinguishable from "never" and would
  # have blamed the compositor for a sampling mistake.
  narf_wl=
  for narf_try in $(seq 1 60); do
    for narf_sock in "$XDG_RUNTIME_DIR"/wayland-[0-9]*; do
      case "$narf_sock" in *.lock) continue ;; esac
      [ -S "$narf_sock" ] || continue
      narf_wl=${narf_sock##*/}
      break
    done
    [ -n "$narf_wl" ] && break
    [ $((narf_try % 15)) -eq 0 ] &&
      echo "PLASMA-FORCE-UNITS: still no wayland socket (${narf_try}s)"
    /usr/bin/sleep 1
  done
  if [ -n "$narf_wl" ]; then
    echo "PLASMA-FORCE-UNITS: publishing WAYLAND_DISPLAY=$narf_wl"
    systemctl --user set-environment "WAYLAND_DISPLAY=$narf_wl" 2>&1 \
      | sed 's/^/PLASMA-FORCE-UNITS: /' | head -5
    export WAYLAND_DISPLAY="$narf_wl"
  else
    echo "PLASMA-FORCE-UNITS: NO wayland socket in $XDG_RUNTIME_DIR — kwin never bound one"
    ls -l "$XDG_RUNTIME_DIR" 2>&1 | sed 's/^/PLASMA-FORCE-UNITS: /' | head -12
  fi
  echo "PLASMA-FORCE-UNITS: manager environment after publish"
  systemctl --user show-environment 2>&1 \
    | grep -iE "WAYLAND|DISPLAY|XDG_|QT_QPA" \
    | sed 's/^/PLASMA-FORCE-UNITS: /' | head -12
  echo "PLASMA-FORCE-UNITS: starting plasma-kded6.service"
  systemctl --user start plasma-kded6.service 2>&1 \
    | sed 's/^/PLASMA-FORCE-UNITS: /' | head -8
  echo "PLASMA-FORCE-UNITS: starting plasma-plasmashell.service"
  systemctl --user start plasma-plasmashell.service 2>&1 \
    | sed 's/^/PLASMA-FORCE-UNITS: /' | head -8
  echo "PLASMA-FORCE-UNITS: start rc above; unit state follows"
  systemctl --user list-units --no-pager --no-legend 'plasma-*' 2>&1 \
    | sed 's/^/PLASMA-FORCE-UNITS: /' | head -25
  systemctl --user list-units --failed --no-pager --no-legend 2>&1 \
    | sed 's/^/PLASMA-FORCE-UNITS-FAILED: /' | head -15
) &

# Give the monitor time to install its match rules before startplasma can
# launch KWin and submit the environment-update batch. This also lets the
# independent GLib waiter and classic supervisor install their matches before
# kded can be started.
/usr/bin/sleep 1
exec /usr/bin/startplasma-wayland
