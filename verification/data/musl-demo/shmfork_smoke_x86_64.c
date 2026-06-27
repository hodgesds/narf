// shmfork_smoke — MAP_SHARED|MAP_ANONYMOUS + fork stop-propagation.
//
// REPRO for an OPEN bug (deterministic, reproduces even at NARF_QEMU_SMP=1):
// a write to a MAP_SHARED|MAP_ANONYMOUS page made from a SIGNAL HANDLER is not
// observed by forked children, even though a DIRECT write to the same page is.
// This is the kernel-level cause of the SMP `chroot_run` (stress-ng) hang: a
// worker spins on a shared "keep going" flag whose stop-write is driven from
// the parent's SIGALRM handler, so the worker never stops.
//
// Two phases over ONE shared page:
//   phase1-direct  (control): parent forks NKIDS spinners, then writes the
//                  sentinel DIRECTLY. Children observe it -> OK. Proves the
//                  MAP_SHARED frame is aliased into the children and coherent.
//   phase2-sigalrm (bug):     parent forks NKIDS spinners, arms
//                  setitimer(ITIMER_REAL) and blocks in waitpid; its SIGALRM
//                  handler writes the same shared page. The handler RUNS (it
//                  reads its own write back as SENTINEL) yet the children never
//                  observe it and spin to the cap -> TIMEOUT.
//
// What was ruled out while narrowing this (see the session notes): signal
// delivery itself works (the handler runs), the itimer fires, the parent's CR3
// at delivery equals its normal CR3, no COW fault hits the shared page, no
// demand-fault hits the shared region, and the page tables show parent AND each
// child mapping the SAME shared frame R/W both at fork+materialize and at
// delivery time. The remaining question: why the child reads stale-0 from a
// frame the page tables say it shares with the parent.
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
// bounded so the buggy phase terminates (a few seconds) instead of hanging.
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
        struct itimerval it = {0};
        it.it_value.tv_usec = 200000; // 200ms one-shot
        setitimer(ITIMER_REAL, &it, 0);
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

    int ok = p1 && p2;
    printf("SHMFORK: %s\n", ok ? "ALL-CHILDREN-SAW-FLAG" : "SOME-CHILD-TIMEOUT");
    return ok ? 0 : 1;
}
