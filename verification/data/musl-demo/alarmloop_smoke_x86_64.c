// Preemptive SIGALRM to a CPU-bound task. A program that arms a real
// interval timer (setitimer ITIMER_REAL) and then spins in a tight loop
// with NO syscalls must still receive SIGALRM. NARF raises it straight
// from the timer ISR (alloc-free, mirroring Linux's it_real_fn) and
// delivers it on the timer-IRQ return to user — without that, the busy
// loop has no yield point and would never see the signal. This is the
// "(a)" half of preemptive signals. Success token "alarmloop-ok".
//
// Build: see REGEN_alarmloop_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>

static volatile sig_atomic_t got = 0;
static void on_alarm(int sig) { (void)sig; got = 1; }

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    if (sigaction(SIGALRM, &sa, 0) != 0) {
        w("alarmloop-fail: sigaction\n");
        return 1;
    }
    // 50 ms repeating real timer. Repeating (not one-shot) so a missed
    // first expiry still gets a later chance instead of wedging.
    struct itimerval it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = 50000;
    it.it_interval.tv_usec = 50000;
    if (setitimer(ITIMER_REAL, &it, 0) != 0) {
        w("alarmloop-fail: setitimer\n");
        return 1;
    }
    // Busy-loop with NO syscalls. The only way SIGALRM can arrive here is
    // preemptively, on a timer-IRQ return to user. Bounded so a kernel
    // WITHOUT preemptive raise+deliver exits with a fail token instead of
    // hanging the harness rather than spinning forever.
    volatile unsigned long n = 0;
    while (!got && n < 3000000000UL) {
        n++;
    }
    // Disarm so we don't leave a repeating timer firing into the shared
    // console after we return.
    struct itimerval off;
    memset(&off, 0, sizeof off);
    setitimer(ITIMER_REAL, &off, 0);
    if (got) {
        w("alarmloop-ok\n");
    } else {
        w("alarmloop-fail: no SIGALRM in busy loop\n");
    }
    return 0;
}
