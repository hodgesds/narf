// sched_setattr / sched_getattr smoke. musl ships no wrappers for these,
// so issue them raw with a hand-rolled struct sched_attr. Set a policy +
// nice + priority, read them back. Success token "schedattr-ok".
//
// Build: see REGEN_schedattr_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

struct sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

int main(void) {
    struct sched_attr a;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    a.sched_policy = 0; // SCHED_NORMAL
    a.sched_nice = 5;
    a.sched_priority = 0;
    if (syscall(SYS_sched_setattr, 0, &a, 0u) != 0) { w("schedattr-fail: set\n"); return 1; }

    struct sched_attr b;
    memset(&b, 0xff, sizeof b);
    if (syscall(SYS_sched_getattr, 0, &b, (unsigned)sizeof b, 0u) != 0) {
        w("schedattr-fail: get\n"); return 1;
    }
    if (b.size != sizeof b) { w("schedattr-fail: size\n"); return 1; }
    if (b.sched_policy != 0) { w("schedattr-fail: policy\n"); return 1; }
    if (b.sched_nice != 5) { w("schedattr-fail: nice\n"); return 1; }

    // Too-small a buffer must be rejected.
    char tiny[8];
    if (syscall(SYS_sched_getattr, 0, tiny, 8u, 0u) != -1) {
        w("schedattr-fail: smallbuf\n"); return 1;
    }

    w("schedattr-ok\n");
    return 0;
}
