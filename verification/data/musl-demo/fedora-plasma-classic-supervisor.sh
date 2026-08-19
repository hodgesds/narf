#!/bin/bash
# Complete Plasma's classic startup sequence after its kded6 D-Bus watcher.
set -eu

echo "narf-plasma: supervisor pid=$$ runtime=${XDG_RUNTIME_DIR:-unset}"

# KWin creates the compositor socket asynchronously.  Starting a Qt Wayland
# daemon before it is accepting connections makes Qt abort in platform-plugin
# initialisation, which then leaves the desktop at KWin's black first frame.
for _ in $(seq 1 60); do
  for socket in "$XDG_RUNTIME_DIR"/wayland-[0-9]*; do
    case "$socket" in *.lock) continue ;; esac
    [ -S "$socket" ] || continue
    export WAYLAND_DISPLAY="${socket##*/}"
    break 2
  done
  /usr/bin/sleep 1
done
[ -n "${WAYLAND_DISPLAY:-}" ] || exit 1
echo "narf-plasma: Wayland socket $WAYLAND_DISPLAY ready"

# The classic path normally activates kded6 through a user-unit callback.
# NARF bypasses that incomplete graph, so launch it only after KWin is ready.
/usr/bin/kded6 &
/usr/bin/plasma_waitforname --timeout 45 org.kde.kded6 || exit 1
echo "narf-plasma: kded6 ready"

/usr/bin/ksmserver &
ksm_pid=$!
/usr/bin/plasma_waitforname --timeout 120 org.kde.ksmserver &
ksm_wait_pid=$!

completed_pid=
if wait -n -p completed_pid "$ksm_pid" "$ksm_wait_pid"; then
  status=0
else
  status=$?
fi
if [ "$completed_pid" = "$ksm_pid" ]; then
  kill "$ksm_wait_pid" 2>/dev/null || true
  # KSMServer forcibly selects XCB.  Xwayland is not a desktop requirement
  # here, so its known SIGABRT must not prevent native-Wayland plasmashell.
  [ "$status" -eq 134 ] || exit "$status"
elif [ "$completed_pid" != "$ksm_wait_pid" ] || [ "$status" -ne 0 ]; then
  kill "$ksm_pid" 2>/dev/null || true
  wait "$ksm_pid" 2>/dev/null || true
  exit "$status"
fi
echo "narf-plasma: ksmserver ready"

# A listening Wayland socket is only KWin's early backend milestone.  The
# workspace starts accepting and configuring xdg toplevels once the wrapper
# has acquired its session-bus name; this is the dependency encoded by
# Fedora's plasma-kwin_wayland.service as well.  Starting clients earlier
# leaves them connected but indefinitely awaiting xdg_surface.configure.
if /usr/bin/plasma_waitforname --timeout 45 org.kde.KWinWrapper; then
  echo "narf-plasma: KWin workspace ready"
else
  echo "narf-plasma: KWin wrapper did not announce readiness; continuing" >&2
fi

# Plasma refuses to load its shell without org.kde.ActivityManager.  Fedora
# normally starts this through its user-unit graph, but this image deliberately
# uses the classic path while that graph is still incomplete on NARF.  Start
# the daemon directly and wait for its real D-Bus readiness before allowing
# plasmashell to build a scene.
if [ -x /usr/libexec/kactivitymanagerd ]; then
  /usr/libexec/kactivitymanagerd &
  /usr/bin/plasma_waitforname --timeout 45 org.kde.ActivityManager
fi
echo "narf-plasma: activity manager ready"

# Start an ordinary Wayland terminal alongside the desktop shell.  It is both
# useful immediately and an independent input/surface path while Plasma's
# panel and wallpaper finish loading.
/usr/bin/plasmashell &
plasmashell_pid=$!
echo "narf-plasma: plasmashell pid=$plasmashell_pid"
if [ -x /usr/bin/foot ]; then
  /usr/bin/foot -- /bin/bash --noprofile --norc -i &
  echo "narf-plasma: foot pid=$!"
fi
if wait "$plasmashell_pid"; then
  echo "narf-plasma: plasmashell exited cleanly"
else
  status=$?
  echo "narf-plasma: plasmashell exited status=$status"
  exit "$status"
fi
