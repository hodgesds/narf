// membarrier(2) + clock_getres(2) smoke. membarrier QUERY returns a
// non-zero supported-command mask and a GLOBAL barrier returns 0;
// clock_getres reports a sane sub-second resolution. Uses the raw
// syscall() form for membarrier so the test doesn't depend on a musl
// wrapper. Success token "barrier-ok".
//
// Build: see REGEN_barrier_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // MEMBARRIER_CMD_QUERY (0) returns the supported-command bitmask.
    long mask = syscall(SYS_membarrier, 0, 0, 0);
    if (mask <= 0) {
        w("barrier-fail: query\n");
        return 1;
    }
    // MEMBARRIER_CMD_GLOBAL (1 << 0) returns 0.
    long g = syscall(SYS_membarrier, 1, 0, 0);
    if (g != 0) {
        w("barrier-fail: global\n");
        return 1;
    }

    struct timespec res;
    memset(&res, 0, sizeof res);
    if (clock_getres(CLOCK_MONOTONIC, &res) != 0) {
        w("barrier-fail: getres\n");
        return 1;
    }
    if (res.tv_sec == 0 && res.tv_nsec > 0 && res.tv_nsec < 1000000000) {
        w("barrier-ok\n");
    } else {
        w("barrier-fail: res\n");
    }
    return 0;
}
