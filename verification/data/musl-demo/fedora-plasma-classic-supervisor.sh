#!/bin/bash
# NARF acceptance-image bridge for Plasma 6.7.3's classic startup sequence.
#
# plasma_session successfully launches kded6, but its StartServiceJob does not
# advance after the persistent QDBusServiceWatcher observes the registered
# name. The same Fedora Qt watcher completes in plasma_waitforname, so resume
# only the two following process gates here. Keep every transition explicit so
# a later failure cannot be mistaken for the original callback problem.

echo "PLASMA-CLASSIC-SUPERVISOR waiting for kded"
/usr/bin/plasma_waitforname --timeout -1 org.kde.kded6
status=$?
if [ "$status" -ne 0 ]; then
  echo "PLASMA-CLASSIC-SUPERVISOR kded wait failed status=$status"
  exit "$status"
fi

echo "PLASMA-CLASSIC-SUPERVISOR kded observed; launching ksmserver"
/usr/bin/ksmserver &
ksm_pid=$!
echo "PLASMA-CLASSIC-SUPERVISOR ksmserver pid=$ksm_pid"

/usr/bin/plasma_waitforname --timeout 120 org.kde.ksmserver &
ksm_wait_pid=$!
completed_pid=
wait -n -p completed_pid "$ksm_pid" "$ksm_wait_pid"
status=$?

if [ "$completed_pid" = "$ksm_pid" ]; then
  echo "PLASMA-CLASSIC-SUPERVISOR ksmserver exited before name status=$status"
  kill "$ksm_wait_pid" 2>/dev/null
  if [ "$status" -ne 134 ]; then
    exit "$status"
  fi
  echo "PLASMA-CLASSIC-SUPERVISOR bypassing forced-XCB ksmserver abort"
elif [ "$completed_pid" != "$ksm_wait_pid" ] || [ "$status" -ne 0 ]; then
  echo "PLASMA-CLASSIC-SUPERVISOR ksm wait failed pid=$completed_pid status=$status"
  kill "$ksm_pid" 2>/dev/null
  wait "$ksm_pid" 2>/dev/null
  exit "$status"
else
  echo "PLASMA-CLASSIC-SUPERVISOR ksm observed"
fi

# The compositor reaches the scanout (kernel DRM telemetry shows SETCRTC +
# PAGE_FLIP blits) but never repaints after startup, so the desktop stays
# black. That has two very different explanations: KWin cannot present a
# CLIENT's surface at all, or plasmashell specifically never produces one.
# Report the socket the clients will use, then run a minimal wl_shm client
# beside the shell so one replay separates those cases.
if [ -z "${WAYLAND_DISPLAY:-}" ]; then
  for sock in "$XDG_RUNTIME_DIR"/wayland-[0-9]*; do
    case "$sock" in
      *.lock) continue ;;
    esac
    [ -S "$sock" ] || continue
    WAYLAND_DISPLAY=${sock##*/}
    export WAYLAND_DISPLAY
    break
  done
fi
echo "PLASMA-CLASSIC-SUPERVISOR WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-<unset>}"

echo "PLASMA-CLASSIC-SUPERVISOR launching plasmashell"
# Scoped to this one process: the question is whether the SHELL builds a
# Wayland surface and attaches buffers, and the compositor's own Qt client
# traffic would only add noise.
QT_LOGGING_RULES="${QT_LOGGING_RULES:-};qt.qpa.wayland.debug=true" \
  /usr/bin/plasmashell &
plasma_pid=$!
echo "PLASMA-CLASSIC-SUPERVISOR plasmashell pid=$plasma_pid"

# foot is a small, self-contained wl_shm client: xdg-shell surface, no Qt,
# no QML, no GPU path. If it paints while plasmashell does not, the
# compositor's client-surface path is fine and the shell is the blocker.
(
  /usr/bin/sleep 20
  echo "PLASMA-CLASSIC-SUPERVISOR launching foot control client"
  # libwayland's own protocol tracer. KWin presents its startup frames and
  # then never repaints, which means it is compositing an empty scene: no
  # client window is ever mapped. This shows the exact request/event where
  # the map handshake stops — in particular whether the client's
  # xdg_surface.configure ever arrives, since without it a client may not
  # attach a buffer and the compositor has nothing to draw.
  WAYLAND_DEBUG=1 \
    /usr/bin/foot --log-level=info /bin/sh -c 'while :; do /usr/bin/sleep 5; done' &
  foot_pid=$!
  echo "PLASMA-CLASSIC-SUPERVISOR foot pid=$foot_pid"
  wait "$foot_pid"
  echo "PLASMA-CLASSIC-SUPERVISOR foot exited status=$?"
) &

# Retain the helper for the shell's lifetime so an early exit is visible in
# the serial record rather than becoming an unobserved background failure.
wait "$plasma_pid"
status=$?
echo "PLASMA-CLASSIC-SUPERVISOR plasmashell exited status=$status"
exit "$status"
