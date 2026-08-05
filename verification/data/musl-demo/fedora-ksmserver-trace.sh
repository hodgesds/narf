#!/bin/bash
# Diagnostic wrapper for the Fedora Plasma acceptance image.
#
# The classic session's ksmserver StartServiceJob is the recorded boundary:
# plasma_session installs the org.kde.ksmserver match but the name is never
# acquired. That has two very different explanations — the job's process was
# never launched (a Qt/KJob continuation defect) or it was launched and died
# before registering (the known forced-XCB abort). Record every launch with
# its parent so one replay can tell them apart.
#
# The real binary keeps its basename so /proc/<pid>/comm stays `ksmserver`
# for the acceptance probe; only its directory changes.
set -u

parent_comm=unknown
[ -r "/proc/$PPID/comm" ] && read -r parent_comm < "/proc/$PPID/comm"
echo "KSM-TRACE launch pid=$$ ppid=$PPID parent=$parent_comm args=$*" >&2

/usr/local/libexec/ksmserver-real/ksmserver "$@"
status=$?

echo "KSM-TRACE exit pid=$$ status=$status" >&2
exit "$status"
