// Credentials-family smoke. Exercises getresuid / getresgid /
// setresuid / setgroups / getgroups end-to-end. NARF tracks a single
// uid/gid surfaced as all three real/effective/saved slots, and has no
// supplementary groups. Success token "creds-ok".
//
// Build: see REGEN_creds_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    uid_t ru, eu, su;
    if (getresuid(&ru, &eu, &su) != 0) {
        w("creds-fail: getresuid\n");
        return 1;
    }
    if (ru != eu || eu != su) {
        w("creds-fail: uid-mismatch\n");
        return 1;
    }

    gid_t rg, eg, sg;
    if (getresgid(&rg, &eg, &sg) != 0) {
        w("creds-fail: getresgid\n");
        return 1;
    }
    if (rg != eg || eg != sg) {
        w("creds-fail: gid-mismatch\n");
        return 1;
    }

    // No-op set (all -1) must succeed.
    if (setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1) != 0) {
        w("creds-fail: setresuid\n");
        return 1;
    }

    // Empty supplementary group list round-trip.
    if (setgroups(0, NULL) != 0) {
        w("creds-fail: setgroups\n");
        return 1;
    }
    int ng = getgroups(0, NULL);
    if (ng < 0) {
        w("creds-fail: getgroups\n");
        return 1;
    }

    w("creds-ok\n");
    return 0;
}
