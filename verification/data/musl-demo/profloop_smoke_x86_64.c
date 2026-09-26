// CPU interval timers to a CPU-bound task. A program that arms
// setitimer(ITIMER_PROF) and spins with NO syscalls must receive SIGPROF
// once it has consumed enough user+sys CPU time; same for ITIMER_VIRTUAL
// and SIGVTALRM (user time). The CPU-clock twin of alarmloop_smoke: NARF
// checks the running task's CPU clocks from the timer tick
// (itimer_cpu_tick, mirroring Linux's run_posix_cpu_timers) — without
// that the spin loop has no yield point and the timers would never fire.
// This is also the mechanism stress-ng --itimer measures. Success token
// "profloop-ok".
//
// Build: see REGEN_profloop_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>

static volatile sig_atomic_t got_prof = 0;
static volatile sig_atomic_t got_vt = 0;
static void on_prof(int sig) { (void)sig; got_prof = 1; }
static void on_vt(int sig) { (void)sig; got_vt = 1; }

static void w(const char *m) { write(1, m, strlen(m)); }

static int arm_and_spin(int which, int signum, void (*handler)(int),
                        volatile sig_atomic_t *got, const char *tag) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    if (sigaction(signum, &sa, 0) != 0) {
        w("profloop-fail: sigaction ");
        w(tag);
        w("\n");
        return -1;
    }
    // 20 ms of CPU time, repeating (a missed first expiry gets a later
    // chance instead of wedging).
    struct itimerval it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = 20000;
    it.it_interval.tv_usec = 20000;
    if (setitimer(which, &it, 0) != 0) {
        w("profloop-fail: setitimer ");
        w(tag);
        w("\n");
        return -1;
    }
    // Busy-loop with NO syscalls: the signal can only arrive via the
    // timer tick's CPU-clock check on IRQ return to user. Bounded so a
    // kernel that never fires exits with a fail token instead of hanging
    // the harness.
    volatile unsigned long n = 0;
    while (!*got && n < 3000000000UL) {
        n++;
    }
    struct itimerval off;
    memset(&off, 0, sizeof off);
    setitimer(which, &off, 0);
    if (!*got) {
        w("profloop-fail: no signal from ");
        w(tag);
        w("\n");
        return -1;
    }
    return 0;
}

int main(void) {
    if (arm_and_spin(ITIMER_PROF, SIGPROF, on_prof, &got_prof, "ITIMER_PROF"))
        return 1;
    if (arm_and_spin(ITIMER_VIRTUAL, SIGVTALRM, on_vt, &got_vt, "ITIMER_VIRTUAL"))
        return 1;
    w("profloop-ok\n");
    return 0;
}
