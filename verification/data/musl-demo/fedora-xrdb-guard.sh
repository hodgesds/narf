#!/bin/bash
# Plasma's phase-zero fonts/style initialization runs xrdb synchronously.
# Keep the optional X11 resource merge from blocking the Wayland desktop when
# Xwayland has failed before servicing the request, while retaining an exact
# serial marker for the real command's start and completion.
set -u

echo "XRDB-GUARD start pid=$$ args=$*" >&2
/usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/xrdb.narf-real "$@"
status=$?
echo "XRDB-GUARD exit pid=$$ status=$status" >&2
if [ "$status" -eq 124 ] || [ "$status" -eq 137 ] || [ "$status" -eq 143 ]; then
  echo "XRDB-GUARD timed out optional X11 resource merge; continuing Wayland session" >&2
  exit 0
fi
exit "$status"
