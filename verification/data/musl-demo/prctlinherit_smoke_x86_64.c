// What a child of fork/clone inherits from prctl state, checked against
// Linux (`copy_process`).
//
// no_new_privs is a task flag `dup_task_struct` copies; securebits live in
// the copied `struct cred`; dumpable is an `mm` flag the child's new mm takes
// from the parent's. NARF kept all three in a per-task table that fork never
// copied, so every child started with no_new_privs = 0, securebits = 0 and
// dumpable = 1 — a sandbox that set no_new_privs and then forked its workers
// handed them back the right to gain privileges through setuid binaries, and
// seccomp filter installation in those workers needed CAP_SYS_ADMIN again.
//
// The parent-death signal is NOT inherited (`p->pdeath_signal = 0`).
//
// Success token "prctlinherit-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef PR_GET_SECUREBITS
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28
#endif
#define SECBIT_NO_SETUID_FIXUP (1 << 2)

static int fails;
#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("prctlinherit-fail: " __VA_ARGS__);                         \
            printf(" (errno=%d)\n", errno);                                    \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static int expect_secbits;

static int state_ok(void) {
    return prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 && prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 &&
           prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == expect_secbits;
}

static void *thread_fn(void *a) {
    *(int *)a = state_ok();
    return 0;
}

int main(void) {
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0, "no_new_privs set at start");
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "PR_SET_NO_NEW_PRIVS");
    CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0, "PR_SET_DUMPABLE 0");
    CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0, "PR_SET_PDEATHSIG");
    // SECBIT_NO_SETUID_FIXUP needs CAP_SETPCAP; only check it when allowed.
    if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP, 0, 0, 0) == 0)
        expect_secbits = SECBIT_NO_SETUID_FIXUP;
    CHECK(state_ok(), "parent state did not take");

    pid_t c = fork();
    if (c == 0) {
        int pdeath = -1;
        prctl(PR_GET_PDEATHSIG, &pdeath, 0, 0, 0);
        if (!state_ok()) _exit(1);
        if (pdeath != 0) _exit(2);
        // And on to a grandchild.
        pid_t g = fork();
        if (g == 0) _exit(state_ok() ? 0 : 3);
        int gs;
        waitpid(g, &gs, 0);
        _exit(WIFEXITED(gs) ? WEXITSTATUS(gs) : 4);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "forked child state (status %#x)", st);

    int thread_ok = 0;
    pthread_t t;
    pthread_create(&t, 0, thread_fn, &thread_ok);
    pthread_join(t, 0);
    CHECK(thread_ok, "thread state");

    if (fails == 0) printf("prctlinherit-ok\n");
    return fails != 0;
}
