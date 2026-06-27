// shmfork_smoke — MAP_SHARED|MAP_ANONYMOUS + signal-driven fork stop-propagation.
//
// Regression test for the SMP `chroot_run` (stress-ng) hang. A parent stops its
// CPU-bound worker children by writing a shared "keep going" flag from a SIGALRM
// handler while blocked in waitpid — the stress-ng pattern. This exercised two
// kernel signal bugs (both fixed; this was NOT a MAP_SHARED coherence bug):
//   (1) setitimer(ITIMER_REAL) SIGALRM was not delivered to a parent parked in
//       waitpid under spinner load — the timer-IRQ check only inspected the
//       interrupted (child) task, and wait4 wasn't signal-interruptible. Fixed:
//       itimer_real_collect_all_due_irq scans every task's ITIMER_REAL from the
//       tick + raise/wake; wait4 registers a signal waker and returns EINTR.
//   (2) the signal mask was never restored on sigreturn, so the auto-blocked
//       SIGALRM stayed masked forever and a SECOND alarm never fired. Fixed:
//       SIGRETURN_SAVED_MASK saved at delivery, restored in sys_sigreturn.
//
// Three phases over ONE shared page (all must print OK):
//   phase1-direct  : parent writes the sentinel DIRECTLY -> children observe it.
//                    Proves the MAP_SHARED frame is aliased + coherent.
//   phase2-sigalrm : parent arms setitimer(ITIMER_REAL) + blocks in waitpid; the
//                    SIGALRM handler writes the shared page. Exercises bug (1).
//   phase3-raise   : parent delivers SIGALRM synchronously via raise(). Running
//                    AFTER phase2, it exercises bug (2) — the mask must have been
//                    restored after phase2's handler or this SIGALRM stays masked.
//
// Not in the musl-demo CI auto-run list (like chroot_run); run manually:
//   XTASK_QEMU_ACCEL=kvm cargo xtask run-interactive --arch=x86_64 \
//       --cmd shmfork_smoke --expect ALL-CHILDREN-SAW-FLAG
//
// Build: musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large (uniform musl-demo recipe).

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define NKIDS 8
#define SENTINEL 0xABCDu
// Spin cap: large enough a coherent write is always seen well before it,
// bounded so a regressed phase terminates (a few seconds) instead of hanging.
#define SPIN_CAP 6000000000ULL

static volatile uint32_t *g_flags; // shared page, NKIDS slots

static void on_alarm(int sig) {
    (void)sig;
    for (int i = 0; i < NKIDS; i++) {
        g_flags[i] = SENTINEL;
    }
}

// Returns 1 if every child observed the sentinel, 0 if any timed out.
static int spawn_and_wait(volatile uint32_t *flags, int via_alarm) {
    for (int i = 0; i < NKIDS; i++) {
        flags[i] = 0;
    }
    pid_t kids[NKIDS];
    for (int i = 0; i < NKIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            for (uint64_t n = 0; n < SPIN_CAP; n++) {
                if (flags[i] == SENTINEL) {
                    _exit(0);
                }
            }
            _exit(2); // never saw the parent's write
        }
        if (p < 0) {
            printf("SHMFORK: FAIL fork %d\n", i);
            return 0;
        }
        kids[i] = p;
    }

    if (via_alarm) {
        // The stop-write is driven from the SIGALRM handler while the parent
        // blocks in waitpid — the stress-ng pattern.
        g_flags = flags;
        struct sigaction sa = {0};
        sa.sa_handler = on_alarm;
        sigaction(SIGALRM, &sa, 0);
        if (via_alarm == 2) {
            // DIAGNOSTIC: deliver SIGALRM SYNCHRONOUSLY via raise() after the
            // children spin up — isolates handler-context write coherence from
            // itimer SIGALRM delivery to a parked parent.
            for (volatile uint64_t d = 0; d < 20000000ULL; d++) {
            }
            raise(SIGALRM);
        } else {
            struct itimerval it = {0};
            it.it_value.tv_usec = 200000; // 200ms one-shot
            setitimer(ITIMER_REAL, &it, 0);
        }
    } else {
        // Control: direct write after letting the children start spinning.
        for (volatile uint64_t d = 0; d < 20000000ULL; d++) {
        }
        for (int i = 0; i < NKIDS; i++) {
            flags[i] = SENTINEL;
        }
    }

    int ok = 1;
    for (int i = 0; i < NKIDS; i++) {
        int st = 0;
        while (waitpid(kids[i], &st, 0) < 0) {
        } // retry across EINTR from the SIGALRM
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            ok = 0;
        }
    }
    return ok;
}

int main(void) {
    volatile uint32_t *flags = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (flags == MAP_FAILED) {
        printf("SHMFORK: FAIL mmap\n");
        return 1;
    }

    int p1 = spawn_and_wait(flags, 0);
    printf("SHMFORK: phase1-direct %s\n", p1 ? "OK" : "TIMEOUT");
    int p2 = spawn_and_wait(flags, 1);
    printf("SHMFORK: phase2-sigalrm %s\n", p2 ? "OK" : "TIMEOUT");
    int p3 = spawn_and_wait(flags, 2);
    printf("SHMFORK: phase3-raise %s\n", p3 ? "OK" : "TIMEOUT");

    int ok = p1 && p2 && p3;
    printf("SHMFORK: %s\n", ok ? "ALL-CHILDREN-SAW-FLAG" : "SOME-CHILD-TIMEOUT");
    return ok ? 0 : 1;
}
