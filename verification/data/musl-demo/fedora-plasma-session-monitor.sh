#!/bin/bash
# Fedora Plasma session entry point for the NARF desktop image.
#
# This stays on Plasma's classic startup path.  It is the path that starts
# reliably on NARF today and avoids queuing a second, competing set of user
# units while the Linux-compat systemd service implementation is incomplete.
set -eu

echo "narf-plasma: session monitor pid=$$"

narf_uid=$(id -u)
narf_runtime_dir="/run/user/$narf_uid"
narf_user_bus="$narf_runtime_dir/bus"

export XDG_RUNTIME_DIR="$narf_runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$narf_user_bus"

# PID 1 orders this service after user@1000.service.  Do a short real
# round-trip nonetheless: a socket inode alone is not a usable D-Bus session.
for _ in $(seq 1 30); do
  if [ -S "$narf_user_bus" ] &&
     /usr/bin/timeout 2 /usr/bin/dbus-send --session --print-reply \
       --dest=org.freedesktop.DBus /org/freedesktop/DBus \
       org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
    break
  fi
  /usr/bin/sleep 1
done

if ! [ -S "$narf_user_bus" ] ||
   ! /usr/bin/timeout 2 /usr/bin/dbus-send --session --print-reply \
     --dest=org.freedesktop.DBus /org/freedesktop/DBus \
     org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
  echo "Plasma session bus did not become ready" >&2
  exit 1
fi

# Keep Plasma on its proven direct/classic sequence.  The supervisor bridges
# the one upstream QDBus watcher that does not progress on NARF, then starts
# ksmserver and plasmashell exactly once.
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}"
printf '[General]\nsystemdBoot=false\n' > "${XDG_CONFIG_HOME:-$HOME/.config}/startkderc"
/usr/local/libexec/narf-plasma-classic-supervisor &
echo "narf-plasma: classic supervisor pid=$!"

echo "narf-plasma: starting startplasma-wayland"
exec /usr/bin/startplasma-wayland
