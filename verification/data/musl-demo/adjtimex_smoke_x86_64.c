// adjtimex / clock_adjtime smoke. A read-only query (modes == 0) needs no
// privilege and reports an undisciplined clock — STA_UNSYNC, hence
// TIME_ERROR, with the 100 Hz tick and the read-only precision/tolerance
// fields filled in. Only CLOCK_REALTIME can be adjusted at all; the other
// clocks in posix_clocks[] answer EOPNOTSUPP. Success token "adjtimex-ok".
//
// Build: see REGEN_adjtimex_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/timex.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

// MAXFREQ_SCALED / PPM_SCALE, the tolerance every Linux reports.
#define FREQ_TOLERANCE 32768000

int main(void) {
    struct timex tx;
    memset(&tx, 0, sizeof tx);
    // Poison the read-only fields: the kernel must overwrite all of them.
    tx.maxerror = tx.esterror = tx.precision = tx.tolerance = -1;
    tx.modes = 0; // read-only query, allowed without CAP_SYS_TIME
    int r = adjtimex(&tx);
    if (r != TIME_ERROR) { w("adjtimex-fail: state\n"); return 1; }
    if (!(tx.status & STA_UNSYNC)) { w("adjtimex-fail: status\n"); return 1; }
    if (tx.tick != 10000) { w("adjtimex-fail: tick\n"); return 1; }
    if (tx.precision != 1 || tx.tolerance != FREQ_TOLERANCE) {
        w("adjtimex-fail: readonly fields\n"); return 1;
    }

    // musl omits the clock_adjtime wrapper here; issue it raw.
    struct timex cx;
    memset(&cx, 0, sizeof cx);
    cx.modes = 0;
    r = (int)syscall(SYS_clock_adjtime, CLOCK_REALTIME, &cx);
    if (r != TIME_ERROR) { w("adjtimex-fail: clock_state\n"); return 1; }
    if (cx.tick != 10000) { w("adjtimex-fail: clock_tick\n"); return 1; }

    // CLOCK_MONOTONIC exists but has no .clock_adj: EOPNOTSUPP, not EINVAL
    // (which would claim the clockid itself is malformed) and not success.
    memset(&cx, 0, sizeof cx);
    r = (int)syscall(SYS_clock_adjtime, CLOCK_MONOTONIC, &cx);
    if (r != -1 || errno != EOPNOTSUPP) { w("adjtimex-fail: monotonic\n"); return 1; }

    // Disciplining the clock takes CAP_SYS_TIME. Either answer is correct
    // depending on how this probe was launched; what must not happen is a
    // silent success that changes nothing.
    memset(&tx, 0, sizeof tx);
    tx.modes = ADJ_STATUS;
    tx.status = STA_PLL; // clears STA_UNSYNC
    r = adjtimex(&tx);
    if (r == -1) {
        if (errno != EPERM) { w("adjtimex-fail: status perm\n"); return 1; }
    } else {
        if (r != TIME_OK) { w("adjtimex-fail: synced state\n"); return 1; }
        if (tx.status != STA_PLL) { w("adjtimex-fail: status roundtrip\n"); return 1; }
        // Put the kernel back where it was.
        memset(&tx, 0, sizeof tx);
        tx.modes = ADJ_STATUS;
        tx.status = STA_UNSYNC;
        if (adjtimex(&tx) != TIME_ERROR) { w("adjtimex-fail: restore\n"); return 1; }
    }

    w("adjtimex-ok\n");
    return 0;
}
