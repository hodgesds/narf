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

/usr/bin/plasma_waitforname --timeout 120 org.kde.ksmserver
status=$?
if [ "$status" -ne 0 ]; then
  echo "PLASMA-CLASSIC-SUPERVISOR ksm wait failed status=$status"
  exit "$status"
fi

echo "PLASMA-CLASSIC-SUPERVISOR ksm observed; launching plasmashell"
/usr/bin/plasmashell &
plasma_pid=$!
echo "PLASMA-CLASSIC-SUPERVISOR plasmashell pid=$plasma_pid"

# Retain the helper for the shell's lifetime so an early exit is visible in
# the serial record rather than becoming an unobserved background failure.
wait "$plasma_pid"
status=$?
echo "PLASMA-CLASSIC-SUPERVISOR plasmashell exited status=$status"
exit "$status"
