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

# Give the monitor time to install its match rules before startplasma can
# launch KWin and submit the environment-update batch. This also lets the
# independent GLib waiter and classic supervisor install their matches before
# kded can be started.
/usr/bin/sleep 1
exec /usr/bin/startplasma-wayland
