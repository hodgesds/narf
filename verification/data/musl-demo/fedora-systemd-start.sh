#!/bin/bash
# Fedora KDE/systemd launcher for NARF's ext2 test image.
exec 2>&1
echo "fedora-shell-ran"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:$PATH
export LD_LIBRARY_PATH=/usr/lib64:/lib64:/usr/lib
export container=narf
mount -t tmpfs tmpfs /run 2>/dev/null
mkdir -p /run/lock /tmp/nogen /run/systemd/system
export SYSTEMD_GENERATOR_PATH=/tmp/nogen

# Keep only units that require kernel facilities outside this desktop
# bring-up disabled. udev and tmpfiles intentionally run unmasked: failures
# there are compatibility bugs to fix, not image policy.
ln -sf /dev/null /run/systemd/system/modprobe@.service
ln -sf /dev/null /run/systemd/system/sys-kernel-debug.mount
ln -sf /dev/null /run/systemd/system/sys-kernel-tracing.mount
ln -sf /dev/null /run/systemd/system/systemd-journal-flush.service
ln -sf /dev/null /run/systemd/system/systemd-journald.service
ln -sf /dev/null /run/systemd/system/systemd-journald.socket
ln -sf /dev/null /run/systemd/system/systemd-journald-dev-log.socket
ln -sf /dev/null /run/systemd/system/systemd-journald-audit.socket
ln -sf /dev/null /run/systemd/system/systemd-udev-load-credentials.service
ln -sf /dev/null /run/systemd/system/systemd-update-utmp.service
ln -sf /dev/null /run/systemd/system/getty@tty1.service

# Force every systemd process (incl. sd-executor) to log to the console so
# service-child failures (e.g. the mount-namespace error path in sd-executor,
# normally emitted to /dev/kmsg) are visible on the serial capture.
export SYSTEMD_LOG_TARGET=console
if [ "$$" -eq 1 ]; then
  exec /usr/lib/systemd/systemd --system --log-level=info --log-target=console
else
  unshare -p -f --mount-proc /usr/lib/systemd/systemd --system --log-level=info --log-target=console &
fi

bus_ready=0
for i in $(seq 1 120); do
  if [ "$(cat /sys/fs/cgroup/system.slice/dbus-broker.service/cgroup.procs 2>/dev/null | wc -w)" -ge 1 ] &&
     [ -S /run/dbus/system_bus_socket ]; then
    bus_ready=1
    break
  fi
  if [ $((i % 10)) -eq 0 ]; then
    echo "waiting for system D-Bus ($i/120)"
  fi
  sleep 1
done
if [ "$bus_ready" -ne 1 ]; then
  echo "FED-BLOCKED: system D-Bus did not become ready; Plasma not launched"
  wait
  exit 1
fi

export HOME=/tmp/kde-home
# XDG_RUNTIME_DIR must be /run/user/$UID: that is where systemd's
# user-runtime-dir@.service creates the runtime dir and where the user
# manager publishes its D-Bus socket ($XDG_RUNTIME_DIR/bus). Pointing it at
# an arbitrary /tmp path leaves `systemd --user` and the session looking at
# two different runtime directories, so the user bus is never found.
NARF_UID=$(id -u)
export XDG_RUNTIME_DIR=/run/user/$NARF_UID
export XDG_CACHE_HOME=$HOME/.cache
export XDG_CONFIG_HOME=$HOME/.config
export XDG_DATA_HOME=$HOME/.local/share
export XDG_STATE_HOME=$HOME/.local/state
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" \
         "$XDG_DATA_HOME" "$XDG_STATE_HOME" /tmp/.X11-unix
chmod 0700 "$XDG_RUNTIME_DIR"
chmod 1777 /tmp/.X11-unix
export LANG=C.UTF-8 LC_ALL=C.UTF-8
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# systemdBoot=true: Plasma 6 on Fedora ships its components as systemd USER
# units (plasma-kwin_wayland.service, plasma-plasmashell.service,
# plasma-kactivitymanagerd.service, ...) and startplasma drives them through
# plasma-workspace.target. With systemdBoot=false it takes the legacy path,
# and the units never start — which is why the session bus reported
# `org.kde.Startup` and `org.freedesktop.systemd1` as "not provided by any
# .service files" (x35 and x11), and why org.kde.ActivityManager and
# org.freedesktop.Notifications had only D-Bus activation left and timed out
# at 120 s. Written below only once a user manager is actually running.
NARF_STARTKDERC_SYSTEMD=false
unset WAYLAND_DISPLAY
export KWIN_DRM_NO_AMS=1
export KWIN_DRM_DEVICES=/dev/dri/card0
export QT_QPA_PLATFORM=wayland
export QT_LOGGING_RULES="kwin_*.debug=true"
export XDG_SESSION_TYPE=wayland
export XDG_CURRENT_DESKTOP=KDE
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe

# ── Bring up a real `systemd --user` session ─────────────────────────
#
# Everything below exists because the session previously ran under
# `dbus-run-session`, which creates a bare private bus with NO user manager
# behind it. `org.freedesktop.systemd1` is the user manager's own bus name;
# without it, Plasma's systemd-unit startup path cannot work at all.
#
# user@$UID.service pulls in user-runtime-dir@$UID.service (creates
# /run/user/$UID) and starts `systemd --user`, whose dbus.socket publishes
# the session bus at $XDG_RUNTIME_DIR/bus.
user_bus="$XDG_RUNTIME_DIR/bus"
echo "=== FED-SYSTEMD starting user@$NARF_UID.service ==="
systemctl start "user@$NARF_UID.service" 2>&1 | sed 's/^/FED-USERBUS: /' || true

userbus_ready=0
for i in $(seq 1 60); do
  if [ -S "$user_bus" ]; then
    userbus_ready=1
    break
  fi
  if [ $((i % 10)) -eq 0 ]; then
    echo "FED-USERBUS: waiting for $user_bus ($i/60)"
    systemctl status "user@$NARF_UID.service" --no-pager 2>&1 \
      | sed 's/^/FED-USERBUS: /' | head -12
  fi
  sleep 1
done

if [ "$userbus_ready" -eq 1 ]; then
  echo "FED-USERBUS: user manager is up; session bus at $user_bus"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus"
  NARF_STARTKDERC_SYSTEMD=true
  # The user manager does not inherit our environment. Plasma's units need
  # the graphical session variables, so push them in before starting the
  # session (this is what a real display manager does).
  systemctl --user import-environment \
    HOME XDG_RUNTIME_DIR XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME \
    XDG_STATE_HOME XDG_SESSION_TYPE XDG_CURRENT_DESKTOP PATH LANG LC_ALL \
    QT_QPA_PLATFORM QT_LOGGING_RULES KWIN_DRM_NO_AMS KWIN_DRM_DEVICES \
    LIBGL_ALWAYS_SOFTWARE GALLIUM_DRIVER 2>&1 \
    | sed 's/^/FED-USERBUS: /' || true
else
  # Do NOT pretend this worked. A silent fallback here would leave the same
  # ServiceUnknown/timeout failures with no line in the log saying why.
  echo "FED-USERBUS-FALLBACK: user@$NARF_UID.service never published $user_bus;"
  echo "FED-USERBUS-FALLBACK: falling back to a private dbus-run-session bus."
  echo "FED-USERBUS-FALLBACK: expect org.kde.Startup / org.freedesktop.systemd1"
  echo "FED-USERBUS-FALLBACK: ServiceUnknown and 120s activation timeouts."
fi

printf '[General]\nsystemdBoot=%s\n' "$NARF_STARTKDERC_SYSTEMD" \
  > "$XDG_CONFIG_HOME/startkderc"
echo "=== FED-SYSTEMD launching Plasma (systemdBoot=$NARF_STARTKDERC_SYSTEMD) ==="
if [ "$userbus_ready" -eq 1 ]; then
  startplasma-wayland &
else
  dbus-run-session -- startplasma-wayland &
fi

for i in $(seq 1 60); do
  sleep 5
  spid=$(pgrep -o startplasma 2>/dev/null)
  if [ -n "$spid" ]; then
    set -- $(cat "/proc/$spid/stat" 2>/dev/null)
    spstat="pid=$spid state=$3 cpu=$(( ${14} + ${15} ))"
    childstat=""
    for cpid in $(cat "/proc/$spid/task/$spid/children" 2>/dev/null); do
      set -- $(cat "/proc/$cpid/stat" 2>/dev/null)
      childstat="$childstat pid=$cpid comm=$2 state=$3 cpu=$(( ${14} + ${15} ));"
    done
    [ -n "$childstat" ] || childstat="none"
  else
    spstat="pid=none"
    childstat="none"
  fi
  kpid=$(pgrep -o kwin_wayland 2>/dev/null)
  if [ -n "$kpid" ]; then
    set -- $(cat "/proc/$kpid/stat" 2>/dev/null)
    kwstat="count=$(pgrep -c kwin_wayland 2>/dev/null) pid=$kpid state=$3 cpu=$(( ${14} + ${15} ))"
  else
    kwstat="count=0"
  fi
  bpid=$(pgrep -o dbus-broker 2>/dev/null)
  if [ -n "$bpid" ]; then
    set -- $(cat "/proc/$bpid/stat" 2>/dev/null)
    brokerstat="pid=$bpid state=$3 cpu=$(( ${14} + ${15} ))"
  else
    brokerstat="pid=none"
  fi
  echo "HB $i | dbus=$(cat /sys/fs/cgroup/system.slice/dbus-broker.service/cgroup.procs 2>/dev/null | wc -w) broker=[$brokerstat] startplasma=[$spstat] children=[$childstat] kwin=[$kwstat] plasma=$(pgrep -c plasmashell 2>/dev/null)"
done
