// setitimer(2) / getitimer(2) / alarm(2) smoke. Arm ITIMER_REAL for a
// far-future one-shot and confirm getitimer reports a non-zero remaining
// value, then re-arm a 50 ms one-shot and pause() until the kernel timer
// pump delivers SIGALRM. Finally check alarm() returns the previous
// (unexpired) alarm's remaining seconds. Success token "itimer-ok".
//
// The kernel raises SIGALRM from a sleep-pump while the task is parked
// in pause(); the poll loop breaks the (infinite) park on the pending
// signal and the next pause() re-issue takes delivery.
//
// Build: see REGEN_itimer_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

static volatile sig_atomic_t got_alarm = 0;
static void on_alarm(int sig) { (void)sig; got_alarm = 1; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    if (sigaction(SIGALRM, &sa, 0) != 0) { w("itimer-fail: sigaction\n"); return 1; }

    struct itimerval it;

    // (1) getitimer reports the remaining time of an armed one-shot.
    // Arm a far-future value (1000 s): on a slow TCG / no-TSC-deadline
    // QEMU the wall-clock gap between this setitimer and the getitimer
    // below can be tens of ms, so a short (50 ms) one-shot could legally
    // fire in between and read back zero — a false "getitimer-zero". A
    // 1000 s timer cannot elapse in that window, so the only way to read
    // zero here is a genuine getitimer bug.
    memset(&it, 0, sizeof it);
    it.it_value.tv_sec = 1000;
    if (setitimer(ITIMER_REAL, &it, 0) != 0) { w("itimer-fail: setitimer\n"); return 1; }

    struct itimerval cur;
    memset(&cur, 0, sizeof cur);
    if (getitimer(ITIMER_REAL, &cur) != 0) { w("itimer-fail: getitimer\n"); return 1; }
    if (cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0) {
        w("itimer-fail: getitimer-zero\n"); return 1;
    }

    // (2) signal delivery. Re-arm a short one-shot (this setitimer
    // replaces the 1000 s timer above) and park until SIGALRM lands.
    // Here a fast fire is exactly what we want, so 50 ms is fine.
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = 50000; // 50 ms one-shot
    if (setitimer(ITIMER_REAL, &it, 0) != 0) { w("itimer-fail: setitimer2\n"); return 1; }

    // Park until SIGALRM is delivered. Each pause() either breaks on the
    // now-pending signal (and the next re-issue delivers it) or takes
    // delivery directly. Bounded so a delivery bug fails instead of hangs.
    for (int i = 0; i < 200 && !got_alarm; i++) {
        pause();
    }
    if (!got_alarm) { w("itimer-fail: no-signal\n"); return 1; }

    // alarm() returns the previous alarm's remaining whole seconds.
    alarm(100);
    unsigned int prev = alarm(0); // cancel, read back remaining
    if (prev == 0 || prev > 100) { w("itimer-fail: alarm-remaining\n"); return 1; }

    w("itimer-ok\n");
    return 0;
}
