// Scheduler-policy smoke. musl deliberately stubs the
// sched_{get,set}scheduler / sched_rr_get_interval wrappers to
// -ENOSYS (it doesn't do realtime scheduling), so issue the raw
// syscalls directly: getscheduler reports SCHED_OTHER (0),
// setscheduler(SCHED_OTHER) is accepted, rr_get_interval succeeds.
// Success token "sched-ok".
//
// Build: see REGEN_sched_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    long p = syscall(SYS_sched_getscheduler, 0);
    if (p != 0) { // 0 == SCHED_OTHER
        w("sched-fail: getscheduler\n");
        return 1;
    }
    int prio = 0;
    long s = syscall(SYS_sched_setscheduler, 0, 0 /*SCHED_OTHER*/, &prio);
    if (s != 0) {
        w("sched-fail: setscheduler\n");
        return 1;
    }
    long ts[2] = {0, 0}; // struct timespec
    long r = syscall(SYS_sched_rr_get_interval, 0, ts);
    if (r != 0) {
        w("sched-fail: rr_interval\n");
        return 1;
    }
    w("sched-ok\n");
    return 0;
}
