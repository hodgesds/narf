// Credential gaps smoke: real/effective/fs uid+gid distinction, exercised with
// Linux-LEGAL transitions (NARF enforces the kernel/sys.c privilege model:
// setreuid/setregid may only move an id to one already in {real, effective,
// saved} unless the caller holds CAP_SETUID/CAP_SETGID). The demo starts as root
// (uid 0), which HAS those caps, so it may open a real!=effective split directly;
// but the moment the effective uid leaves 0 the caps are dropped
// (cap_emulate_setxuid), so all privileged sets must happen while still root.
//
// Ordering therefore matters: do the whole GID side first (effective uid is
// still 0, so CAP_SETGID is held and setfsgid may take an arbitrary id), THEN
// the UID side last (setreuid off root drops the caps, so the fs-uid set after
// it must target an id already in {real, effective, saved}). Success token
// "creds2-ok".
//
// Build: see REGEN_creds2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/fsuid.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // ── GID side, while still root (CAP_SETGID held) ──────────────────────
    // setgid as root sets real, effective, and saved gids together.
    if (setgid(50) != 0) { w("creds2-fail: setgid\n"); return 1; }
    if (getgid() != 50 || getegid() != 50) { w("creds2-fail: gid-eq\n"); return 1; }
    // setregid(-1, egid) changes only the effective gid; the saved gid follows.
    if (setregid((gid_t)-1, 60) != 0) { w("creds2-fail: setregid\n"); return 1; }
    if (getgid() != 50 || getegid() != 60) { w("creds2-fail: egid-distinct\n"); return 1; }
    // setfsgid returns the PREVIOUS fs gid (60, tracking the new egid); the new
    // value 70 is arbitrary but permitted because CAP_SETGID is still held.
    if (setfsgid(70) != 60) { w("creds2-fail: setfsgid-prev\n"); return 1; }
    if (setfsgid(-1) != 70) { w("creds2-fail: setfsgid-query\n"); return 1; }

    // ── UID side, LAST (this drops the setid caps) ────────────────────────
    // setreuid(real, eff) as root opens the real!=effective split in one call;
    // afterwards effective uid is 2000, so CAP_SETUID is gone.
    if (setreuid(1000, 2000) != 0) { w("creds2-fail: setreuid\n"); return 1; }
    if (getuid() != 1000) { w("creds2-fail: ruid\n"); return 1; }
    if (geteuid() != 2000) { w("creds2-fail: euid-distinct\n"); return 1; }
    // Unprivileged now: the fs uid may only become one of {real=1000,
    // effective=2000, saved=2000}. setfsuid returns the previous fs uid (2000,
    // which had tracked the new euid), then a query (-1) returns the current.
    if (setfsuid(1000) != 2000) { w("creds2-fail: setfsuid-prev\n"); return 1; }
    if (setfsuid(-1) != 1000) { w("creds2-fail: setfsuid-query\n"); return 1; }

    // getpgrp returns the process-group id (no argument).
    if (getpgrp() < 0) { w("creds2-fail: getpgrp\n"); return 1; }

    w("creds2-ok\n");
    return 0;
}
