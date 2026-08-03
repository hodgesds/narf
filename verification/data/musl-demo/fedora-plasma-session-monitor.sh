#!/bin/bash
# Keep this trace at the D-Bus protocol boundary: KWin's Wayland wrapper does
# not claim org.kde.KWinWrapper until every launch-environment update replies.
# The serial/reply_serial pairs identify the exact request holding that gate.
echo "PLASMA-DBUS-MONITOR starting"
/usr/bin/dbus-monitor --session --monitor \
  "type='method_call',interface='org.kde.Startup',member='updateLaunchEnv'" \
  "type='method_call',interface='org.freedesktop.DBus',member='UpdateActivationEnvironment'" \
  "type='method_call',interface='org.freedesktop.DBus',member='StartServiceByName'" \
  "type='method_call',interface='org.freedesktop.systemd1.Manager',member='SetEnvironment'" \
  "type='method_return'" \
  "type='error'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.KWinWrapper'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.kcminit'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.kded6'" \
  "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.ksmserver'" &

# Give the monitor time to install its match rules before startplasma can
# launch KWin and submit the environment-update batch.
/usr/bin/sleep 1
exec /usr/bin/startplasma-wayland
