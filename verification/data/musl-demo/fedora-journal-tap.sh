#!/bin/bash
# Stream uid-1000's journal to the console, as root.
#
# Plasma's components run as systemd USER units, so everything they print —
# including why kwin exits and takes the whole session down with it via
# plasma-workspace-wayland.target's BindsTo — lands in
# /var/log/journal/<machine-id>/user-1000.journal and NOWHERE else.
#
# That file is unreadable from inside the session: `journalctl --user` as uid
# 1000 fails with "Operation not permitted". Adding
# StandardOutput=journal+console to the user units does not help either — a
# USER unit cannot write /dev/console. Root can read the file, so tap it from
# a system service and mirror it to the console, which is the only channel
# this bring-up can actually capture.
set -u

echo "JTAP: starting; waiting for the user journal to exist"
# The journal file appears only once journald has flushed something for the
# user. Poll rather than assume — an early one-shot check reports "no journal"
# when the truth is "not yet", which reads identically and is wrong.
for i in $(seq 1 120); do
  if journalctl _UID=1000 -n 1 --no-pager >/dev/null 2>&1; then
    echo "JTAP: user journal readable after ${i}s"
    break
  fi
  [ $((i % 30)) -eq 0 ] && echo "JTAP: still waiting for user journal (${i}s)"
  sleep 1
done

# POLL with a cursor, do NOT use `journalctl -f`.
#
# -f produced ZERO output while kwin was demonstrably running and logging:
# journald had renamed and replaced user-1000.journal ("corrupted or uncleanly
# shut down"), and the follow does not pick the new file up. A silent -f is
# indistinguishable from "the unit printed nothing", which is the wrong
# conclusion and the reason this is a poll.
#
# --cursor-file makes each pass resume where the last ended, so nothing is
# replayed and nothing is lost across a rotation. --output=cat drops the
# timestamp/hostname columns, noise on a line systemd already prefixes.
# Match on _SYSTEMD_USER_UNIT, NOT _UID=1000. Our own probe and session
# monitor run as uid 1000 and already print to the console, so a _UID match
# echoed every PLASMA-PROBE / FED-BUSDIAG line back — doubling the noise and
# burying the Plasma output this exists to surface. Those helpers run under a
# SYSTEM unit (narf-plasma.service, so _SYSTEMD_UNIT), whereas the Plasma
# components are real user units, so this filter separates them exactly.
# `+` is journalctl's OR between match groups.
narf_cursor=/run/narf-jtap.cursor
while :; do
  journalctl --cursor-file="$narf_cursor" \
    _SYSTEMD_USER_UNIT=plasma-kwin_wayland.service \
    + _SYSTEMD_USER_UNIT=plasma-plasmashell.service \
    + _SYSTEMD_USER_UNIT=plasma-kded6.service \
    + _SYSTEMD_USER_UNIT=plasma-ksmserver.service \
    + _SYSTEMD_USER_UNIT=plasma-kcminit.service \
    --no-pager --output=cat 2>&1 |
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf 'JTAP: %s\n' "$line"
    done
  sleep 2
done
