// RT-signal regression smoke — covers the three signal fixes behind the
// stress-ng --sigrt hang. Success token "sigrt-ok".
//
//  T1 (si_pid): an SA_SIGINFO handler for a queued (sigqueue) signal must see
//      si_pid == the sender's pid and si_value == the payload. The sigframe
//      builder used to write si_addr at the siginfo union offset 16 for every
//      signal, so a queued signal's handler saw si_pid == 0 (stress-ng's child
//      replied to si_pid and lost its target).
//  T2 (fork-mask): a forked child must start with a CLEAN signal mask. A fork
//      ordering race copied the parent's transient (musl __block_all_sigs)
//      mask over the child's restored one, so a child started with every
//      application signal BLOCKED and its handlers never fired.
//  T3 (sigwait reservation): a child parked in sigwaitinfo on an UNBLOCKED RT
//      signal that also has a handler installed must receive an incoming
//      sigqueue through the WAITER, not the handler (Linux do_sigtimedwait
//      real_blocked). stress-ng --sigrt leaves the RT signals unblocked with
//      nop handlers; without the reservation the nop handler stole the signal
//      and the waiter parked forever.
//
// Build: see REGEN_sigrt_smoke.sh (musl-gcc, PIE).
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

static void w(const char *m) { write(1, m, strlen(m)); }

// T1
static volatile int t1_pid, t1_val;
static void t1_h(int s, siginfo_t *si, void *u) {
    (void)s; (void)u;
    t1_pid = si->si_pid;
    t1_val = si->si_value.sival_int;
}

// T2
static volatile int t2_fired;
static void t2_h(int s) { (void)s; t2_fired = 1; }

// T3
static void t3_nop(int s, siginfo_t *si, void *u) { (void)s; (void)si; (void)u; }

int main(void) {
    // T1: si_pid + si_value on an SA_SIGINFO handler for a queued signal.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = t1_h;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &sa, NULL);
    union sigval v;
    v.sival_int = 0x1234;
    if (sigqueue(getpid(), SIGRTMIN, v) != 0) { w("sigrt-fail: T1 sigqueue\n"); return 1; }
    if (t1_pid != getpid() || t1_val != 0x1234) { w("sigrt-fail: T1 si_pid/si_value\n"); return 1; }
    w("T1-ok\n");

    // T2: a forked child starts with a clean mask, so its handler fires.
    pid_t c = fork();
    if (c == 0) {
        struct sigaction s2;
        memset(&s2, 0, sizeof(s2));
        s2.sa_handler = t2_h;
        sigaction(SIGUSR1, &s2, NULL);
        raise(SIGUSR1);
        _exit(t2_fired ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { w("sigrt-fail: T2 fork-mask/handler\n"); return 1; }
    w("T2-ok\n");

    // T3: the waiter must win an UNBLOCKED in-set sigqueue over a nop handler.
    struct sigaction s3;
    memset(&s3, 0, sizeof(s3));
    s3.sa_sigaction = t3_nop;
    s3.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN + 1, &s3, NULL); // handler installed; signal NOT blocked
    pid_t c2 = fork();
    if (c2 == 0) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGRTMIN + 1);
        siginfo_t info;
        int r = sigwaitinfo(&set, &info);
        _exit((r == SIGRTMIN + 1 && info.si_value.sival_int == 42) ? 0 : 1);
    }
    usleep(200000); // let the child park in sigwaitinfo
    union sigval v2;
    v2.sival_int = 42;
    sigqueue(c2, SIGRTMIN + 1, v2);
    int st2;
    for (int i = 0; i < 50; i++) {
        if (waitpid(c2, &st2, WNOHANG) == c2) goto reaped;
        usleep(100000);
    }
    kill(c2, SIGKILL);
    waitpid(c2, &st2, 0);
    w("sigrt-fail: T3 child hung (waiter lost signal to handler)\n");
    return 1;
reaped:
    if (!WIFEXITED(st2) || WEXITSTATUS(st2) != 0) { w("sigrt-fail: T3 wrong dequeue\n"); return 1; }

    w("sigrt-ok\n");
    return 0;
}
