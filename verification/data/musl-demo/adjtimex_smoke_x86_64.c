// adjtimex / clock_adjtime smoke. A read-only query (modes == 0) must
// return TIME_OK and report the steady-state tick. Success token
// "adjtimex-ok".
//
// Build: see REGEN_adjtimex_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/timex.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define CLOCK_REALTIME 0

int main(void) {
    struct timex tx;
    memset(&tx, 0, sizeof tx);
    tx.modes = 0; // read-only query
    int r = adjtimex(&tx);
    if (r != TIME_OK) { w("adjtimex-fail: state\n"); return 1; }
    if (tx.tick != 10000) { w("adjtimex-fail: tick\n"); return 1; }

    // musl omits the clock_adjtime wrapper here; issue it raw.
    struct timex cx;
    memset(&cx, 0, sizeof cx);
    cx.modes = 0;
    r = (int)syscall(SYS_clock_adjtime, CLOCK_REALTIME, &cx);
    if (r != TIME_OK) { w("adjtimex-fail: clock_state\n"); return 1; }
    if (cx.tick != 10000) { w("adjtimex-fail: clock_tick\n"); return 1; }

    w("adjtimex-ok\n");
    return 0;
}
