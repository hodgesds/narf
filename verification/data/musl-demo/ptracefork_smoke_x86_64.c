// ptrace following children (`strace -f`, gdb's follow-fork), checked
// against Linux.
//
// With PTRACE_O_TRACEFORK / TRACEVFORK / TRACECLONE set, a tracee's fork,
// vfork and clone stop the tracee with SIGTRAP | PTRACE_EVENT_* << 8 (the new
// child's pid via PTRACE_GETEVENTMSG), and the child is attached to the same
// tracer automatically, starting in a SIGSTOP stop. NARF stored the options
// and did none of it: `strace -f chromium` never saw the browser's threads
// and children and hung.
//
// Also: PTRACE_GETSIGINFO at an event stop (si_signo SIGTRAP, si_code the
// stop's code), at a signal-delivery stop (the signal's own siginfo, a
// sigqueue value included), and at a new child's first stop (SIGSTOP);
// GETEVENTMSG's EFAULT; and that every traced thread and child is reaped
// through the tracer's wait (__WALL).
//
// Success token "ptracefork-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK 2
#define PTRACE_O_TRACEVFORK 4
#define PTRACE_O_TRACECLONE 8
#endif
#ifndef PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT 0x40
#endif
#ifndef PTRACE_O_TRACEVFORKDONE
#define PTRACE_O_TRACEVFORKDONE 0x20
#endif
#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#define PTRACE_EVENT_VFORK 2
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_VFORK_DONE 5
#endif
#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 6
#endif
#ifndef PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG 0x4201
#endif
#ifndef PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static int fails;
#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("ptracefork-fail: " __VA_ARGS__);                           \
            printf(" (errno=%d)\n", errno);                                    \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static volatile int usr1_seen;
static void on_usr1(int s, siginfo_t *si, void *uc) {
    (void)s;
    (void)uc;
    if (si->si_value.sival_int == 4242) usr1_seen = 1;
}

static void *thread_fn(void *a) {
    (void)a;
    syscall(SYS_getpid);
    return 0;
}

static void tracee(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(90);
    raise(SIGSTOP);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, 0);

    pid_t c = fork();
    if (c == 0) _exit(7);
    int st;
    while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) _exit(91);

    pthread_t t;
    if (pthread_create(&t, 0, thread_fn, 0) != 0) _exit(92);
    pthread_join(t, 0);

    pid_t v = vfork();
    if (v == 0) _exit(3);
    while (waitpid(v, &st, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 3) _exit(93);

    union sigval val = {.sival_int = 4242};
    sigqueue(getpid(), SIGUSR1, val);
    if (!usr1_seen) _exit(94);
    _exit(0);
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    int debug = getenv("PTRACEFORK_DEBUG") != 0;
    pid_t t = fork();
    if (t == 0) tracee();

    int st;
    if (waitpid(t, &st, 0) != t || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        printf("ptracefork-fail: no initial SIGSTOP\n");
        return 1;
    }
    CHECK(ptrace(PTRACE_SETOPTIONS, t, 0,
                 (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                          PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXIT)) == 0,
          "SETOPTIONS");
    errno = 0;
    CHECK(ptrace(PTRACE_GETEVENTMSG, t, 0, (void *)8) == -1 && errno == EFAULT,
          "GETEVENTMSG to a bad pointer not EFAULT");
    ptrace(PTRACE_CONT, t, 0, 0);

    int ev_fork = 0, ev_vfork = 0, ev_vfork_done = 0, ev_clone = 0, new_stops = 0, usr1_stop = 0;
    int ev_exit = 0, exit_codes = 0, exit_zero = 0;
    int tracee_exit = -1;
    for (int iter = 0; iter < 200; iter++) {
        pid_t p = waitpid(-1, &st, __WALL);
        if (p < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (debug) printf("exit pid=%d status=%#x\n", p, st);
            if (p == t) tracee_exit = st;
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        int sig = WSTOPSIG(st);
        int event = (unsigned)st >> 16;
        if (debug) printf("stop pid=%d sig=%d event=%d\n", p, sig, event);
        siginfo_t si;
        memset(&si, 0, sizeof si);
        if (event) {
            unsigned long msg = 0;
            CHECK(ptrace(PTRACE_GETEVENTMSG, p, 0, &msg) == 0, "GETEVENTMSG");
            CHECK(ptrace(PTRACE_GETSIGINFO, p, 0, &si) == 0 && si.si_signo == SIGTRAP &&
                      si.si_code == (SIGTRAP | (event << 8)),
                  "event %d siginfo signo=%d code=%#x", event, si.si_signo, si.si_code);
            if (event == PTRACE_EVENT_FORK) ev_fork++;
            if (event == PTRACE_EVENT_VFORK) ev_vfork++;
            if (event == PTRACE_EVENT_VFORK_DONE) ev_vfork_done++;
            if (event == PTRACE_EVENT_CLONE) ev_clone++;
            if (event == PTRACE_EVENT_EXIT) {
                // The status the task is about to exit with, as wait reports it.
                if (msg == (7 << 8)) exit_codes |= 1;  // forked child
                if (msg == (3 << 8)) exit_codes |= 2;  // vfork child
                if (msg == 0) exit_zero++;             // thread + tracee
                ev_exit++;
                ptrace(PTRACE_CONT, p, 0, 0);
                continue;
            }
            CHECK(msg > 0, "event %d message (the new child's pid) %lu", event, msg);
            ptrace(PTRACE_CONT, p, 0, 0);
            continue;
        }
        if (sig == SIGSTOP && p != t) {
            // An auto-attached child's first stop. It may arrive before or
            // after its parent's event stop, as on Linux: the two tasks race.
            CHECK(ptrace(PTRACE_GETSIGINFO, p, 0, &si) == 0 && si.si_signo == SIGSTOP,
                  "new child's first stop siginfo signo=%d", si.si_signo);
            new_stops++;
            ptrace(PTRACE_CONT, p, 0, 0);
            continue;
        }
        if (sig == SIGUSR1) {
            CHECK(ptrace(PTRACE_GETSIGINFO, p, 0, &si) == 0 && si.si_signo == SIGUSR1 &&
                      si.si_code == SI_QUEUE && si.si_value.sival_int == 4242,
                  "SIGUSR1 siginfo signo=%d code=%d val=%d", si.si_signo, si.si_code,
                  si.si_value.sival_int);
            usr1_stop++;
            ptrace(PTRACE_CONT, p, 0, (void *)(long)SIGUSR1);
            continue;
        }
        // Any other signal-delivery stop (SIGCHLD to the tracee): pass it on.
        ptrace(PTRACE_CONT, p, 0, (void *)(long)(sig == SIGSTOP ? 0 : sig));
    }
    CHECK(ev_fork == 1, "fork events %d", ev_fork);
    CHECK(ev_vfork == 1, "vfork events %d", ev_vfork);
    CHECK(ev_vfork_done == 1, "vfork-done events %d", ev_vfork_done);
    CHECK(ev_clone == 1, "clone events %d", ev_clone);
    CHECK(new_stops == 3, "auto-attached children's SIGSTOP stops %d", new_stops);
    CHECK(usr1_stop == 1, "SIGUSR1 delivery stops %d", usr1_stop);
    CHECK(ev_exit == 4 && exit_codes == 3 && exit_zero == 2,
          "PTRACE_EVENT_EXIT stops %d codes %#x zero %d", ev_exit, exit_codes, exit_zero);
    CHECK(tracee_exit != -1 && WIFEXITED(tracee_exit) && WEXITSTATUS(tracee_exit) == 0,
          "tracee exit status %#x", tracee_exit);
    if (fails == 0) printf("ptracefork-ok\n");
    return fails != 0;
}
