#!/bin/bash
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
  if /usr/bin/gdbus wait --session org.kde.kded6; then
    echo "PLASMA-GDBUS-WAIT kded observed"
  else
    status=$?
    echo "PLASMA-GDBUS-WAIT kded failed status=$status"
  fi
) &

# Exercise the exact Qt QDBusServiceWatcher implementation independently of
# plasma_session's StartServiceJob. If this exits while StartServiceJob remains
# pending, the remaining defect is in Plasma's job/callback context rather
# than Qt's bus match and signal-delivery machinery as a whole.
(
  echo "PLASMA-QT-WAIT kded start"
  if /usr/bin/plasma_waitforname --timeout -1 org.kde.kded6; then
    echo "PLASMA-QT-WAIT kded observed"
  else
    status=$?
    echo "PLASMA-QT-WAIT kded failed status=$status"
  fi
) &

# Give the monitor time to install its match rules before startplasma can
# launch KWin and submit the environment-update batch. This also lets the
# independent GLib and Qt name waiters install their matches before kded can
# be started.
/usr/bin/sleep 1
exec /usr/bin/startplasma-wayland
