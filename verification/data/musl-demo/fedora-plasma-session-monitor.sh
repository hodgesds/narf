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
    if [ -S "$narf_user_bus" ]; then
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
  if [ "$narf_bus_ready" -eq 1 ]; then
    echo "FED-USERBUS: user manager up; session bus at $narf_user_bus"
    # XDG_RUNTIME_DIR must agree with where the manager published its
    # socket, or the session and the manager look at different runtime dirs.
    export XDG_RUNTIME_DIR="/run/user/$narf_uid"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$narf_user_bus"
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
