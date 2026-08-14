#!/bin/bash
# Focused distro integration gate: prove that real systemd-udevd persists the
# primary DRM device's seat tag and that real logind consumes it. Plasma is an
# acceptance test downstream of this contract, not the diagnostic mechanism.

set -u

db=/run/udev/data/c226:0
seat_path=/org/freedesktop/login1/seat/seat0

for _ in $(seq 1 20); do
    db_ready=0
    graphical=0

    if [ -s "$db" ] && grep -q '^G:master-of-seat$' "$db"; then
        db_ready=1
    fi
    if busctl get-property \
        org.freedesktop.login1 \
        "$seat_path" \
        org.freedesktop.login1.Seat \
        CanGraphical 2>/dev/null | grep -q '^b true$'; then
        graphical=1
    fi

    if [ "$db_ready" -eq 1 ] && [ "$graphical" -eq 1 ]; then
        echo "NARF_UDEV_SEAT_PASS card0=master-of-seat CanGraphical=yes"
        exit 0
    fi
    sleep 1
done

if [ -e "$db" ]; then
    sed -n '1,160p' "$db"
else
    echo "missing=$db"
fi
busctl get-property \
    org.freedesktop.login1 \
    "$seat_path" \
    org.freedesktop.login1.Seat \
    CanGraphical 2>&1 || true
loginctl seat-status seat0 2>&1 || true
systemctl --no-pager --full status systemd-udevd.service systemd-logind.service \
    2>&1 || true
journalctl --no-pager -b -u systemd-udevd.service 2>&1 || true

# Diagnostic A/B only: if the boot-time queued coldplug was lost, a fresh DRM
# trigger against the already-running daemon distinguishes replay/activation
# loss from rule/database-write failure. The gate still fails either way.
echo "narf-udev-seat-gate: retrying one explicit DRM coldplug"
udevadm trigger --action=add --subsystem-match=drm 2>&1 || true
udevadm settle --timeout=5 2>&1 || true
if [ -e "$db" ]; then
    echo "narf-udev-seat-gate: database appeared after explicit retrigger"
    sed -n '1,160p' "$db"
else
    echo "narf-udev-seat-gate: database still missing after explicit retrigger"
fi
busctl get-property \
    org.freedesktop.login1 \
    "$seat_path" \
    org.freedesktop.login1.Seat \
    CanGraphical 2>&1 || true
echo "NARF_UDEV_SEAT_FAIL db=$db"
exit 1
