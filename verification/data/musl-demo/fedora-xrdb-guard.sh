#!/bin/bash
# Plasma's phase-zero fonts/style initialization runs xrdb synchronously.
# Keep the optional X11 resource merge from blocking the Wayland desktop when
# Xwayland has failed before servicing the request.
set -u

# kcminit_startup's Wayland guard deliberately clears DISPLAY.  xrdb has no
# useful work in that environment; treating its immediate "Can't open display"
# failure as a startup failure can prevent the native Wayland session from
# reaching kded/plasmashell.
if [ -z "${DISPLAY:-}" ]; then
  exit 0
fi

/usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/xrdb.narf-real "$@"
status=$?
if [ "$status" -eq 124 ] || [ "$status" -eq 137 ] || [ "$status" -eq 143 ]; then
  exit 0
fi
exit "$status"
