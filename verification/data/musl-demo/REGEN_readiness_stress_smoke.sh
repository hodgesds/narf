#!/bin/sh
# Rebuild the readiness stress reproducer: lost/late wakeups and lost bytes in
# the poll / epoll / pty / AF_UNIX socket / futex / wait4 paths, driven by
# tmux-like pty relay chains into a fish-like shell, a resolved-like epoll
# loop, a Mesa util_queue-like futex queue and a Bash-tool-like child-exit
# loop, all at once on pinned CPUs (see the header of the .c file).
#
# Statically linked on purpose: the guest needs no /lib/ld-*.so for a static
# binary (see REGEN_tmpfs_share_smoke.sh). The binary is NOT committed (a
# static glibc build is ~1.2 MB); build it where you need it:
#
#   gcc -O2 -Wall -static -pthread readiness_stress_smoke_x86_64.c -o readiness_stress_smoke_x86_64
#
# It must pass on the host's real Linux kernel first: every assertion in it
# is a Linux semantic, so a failure there means the TEST is wrong. Running
# two copies at once on the host is a good extra-load check:
#
#   ./readiness_stress_smoke_x86_64 60 & ./readiness_stress_smoke_x86_64 60; wait
#
# Then run it against NARF (QEMU, 16 vCPUs), staged at /usr/bin/rstress:
#
#   XTASK_STAGE_BIN=$PWD/readiness_stress_smoke_x86_64:usr/bin/rstress \
#     cargo narf run run-interactive --cmd '/usr/bin/rstress 240' \
#       --expect readiness-stress-ok --features boot-init
#
# Usage: rstress [seconds [seed]]   (default 240 s; the seed defaults to a
# constant + pid and is printed in the failure dump, so a run's stream and
# stimulus choices can be replayed).
#
# Success: exactly one line, exit 0:
#   readiness-stress-ok chains=3 bytes=N maxrtt_ms=M late=K epoll_events=N
#     futex_jobs=N children=N ipv6=yes|no
# Failure: "readiness-stress FAIL <component>: <reason>" for the first failure
# (a lost/reordered byte, or a component without progress for 3 s), then a
# state dump: every process/thread's phase word (what it is blocked in) with
# /proc state, wchan and syscall, and FIONREAD + poll revents + fdinfo of
# every fd the parent holds. All children are killed; exit 1. It never hangs
# (alarm at seconds + 30).
set -eu
cd "$(dirname "$0")"
CC=${CC:-gcc}
$CC -O2 -Wall -static -pthread readiness_stress_smoke_x86_64.c -o readiness_stress_smoke_x86_64
echo "built readiness_stress_smoke_x86_64"
