// Preemptive scheduling: a CPU-bound child must not stall the parent.
// The parent forks a child that spins in a tight loop with NO syscalls,
// then nanosleeps for 200 ms and checks (via CLOCK_MONOTONIC) that the
// sleep returned promptly. On a purely cooperative executor the spinning
// child never returns from its own poll, so the executor never re-polls
// the parent and the parent's 200 ms sleep is stretched to the child's
// full multi-second spin. With timer-driven preemption ("(b)") the child
// is sliced out every tick, the parent is re-polled, and its self-driven
// sleep deadline fires on time. Success token "preemptsched-ok".
//
// Also exercises delivering SIGKILL to a busy task: the parent kills the
// still-spinning child, which can only take the signal via preemptive
// delivery (deliver_preemptible_signals on the timer-IRQ return).
//
// Build: see REGEN_preemptsched_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>

static void w(const char *m) { write(1, m, strlen(m)); }

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        w("preemptsched-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        // Child: spin a long but bounded time with NO syscalls, then exit.
        // Bounded so a regression eventually proceeds instead of hanging.
        volatile unsigned long n = 0;
        while (n < 2000000000UL) {
            n++;
        }
        _exit(0);
    }

    // Parent: sleep 200 ms. If the child can't be preempted this blows out
    // to the child's full spin time.
    long t0 = now_ms();
    struct timespec req = {0, 200L * 1000 * 1000}, rem;
    nanosleep(&req, &rem);
    long elapsed = now_ms() - t0;

    if (elapsed < 1500) {
        w("preemptsched-ok\n");
    } else {
        w("preemptsched-fail: sleep stalled by CPU-bound child\n");
    }

    // Tear the (possibly still-spinning) child down and reap it.
    kill(pid, SIGKILL);
    int st;
    waitpid(pid, &st, 0);
    return 0;
}
