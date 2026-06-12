// Credential gaps smoke: real/effective/fs uid+gid distinction.
// Exercises geteuid/getegid/getpgrp + setreuid/setregid (which change the
// effective id independently of the real id) + setfsuid/setfsgid (which
// return the previous fs id). NARF enforces no privileges, so every set
// succeeds and the real≠effective split is observable. Success token
// "creds2-ok".
//
// (Runs cleanly only where these sets are unrestricted — i.e. NARF; a
// host as non-root would be blocked, which is expected.)
//
// Build: see REGEN_creds2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/fsuid.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // setuid sets real, effective, and fs uids together.
    if (setuid(1000) != 0) { w("creds2-fail: setuid\n"); return 1; }
    if (getuid() != 1000 || geteuid() != 1000) { w("creds2-fail: uid-eq\n"); return 1; }

    // setreuid(-1, euid) changes only the effective uid.
    if (setreuid((uid_t)-1, 2000) != 0) { w("creds2-fail: setreuid\n"); return 1; }
    if (getuid() != 1000) { w("creds2-fail: ruid-moved\n"); return 1; }
    if (geteuid() != 2000) { w("creds2-fail: euid-distinct\n"); return 1; }

    // setfsuid returns the PREVIOUS fs uid (2000, tracking the new euid),
    // then a query (-1) returns the current.
    if (setfsuid(3000) != 2000) { w("creds2-fail: setfsuid-prev\n"); return 1; }
    if (setfsuid(-1) != 3000) { w("creds2-fail: setfsuid-query\n"); return 1; }

    // gid side mirrors the uid side.
    if (setgid(50) != 0) { w("creds2-fail: setgid\n"); return 1; }
    if (getgid() != 50 || getegid() != 50) { w("creds2-fail: gid-eq\n"); return 1; }
    if (setregid((gid_t)-1, 60) != 0) { w("creds2-fail: setregid\n"); return 1; }
    if (getgid() != 50 || getegid() != 60) { w("creds2-fail: egid-distinct\n"); return 1; }
    if (setfsgid(70) != 60) { w("creds2-fail: setfsgid-prev\n"); return 1; }
    if (setfsgid(-1) != 70) { w("creds2-fail: setfsgid-query\n"); return 1; }

    // getpgrp returns the process-group id (no argument).
    if (getpgrp() < 0) { w("creds2-fail: getpgrp\n"); return 1; }

    w("creds2-ok\n");
    return 0;
}
