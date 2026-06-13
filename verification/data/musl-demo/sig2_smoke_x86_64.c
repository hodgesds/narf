// Signal-queueing smoke: signalfd4 + rt_sigqueueinfo + rt_tgsigqueueinfo,
// including siginfo-payload preservation (si_code + si_value/sigval).
// Block SIGUSR1, queue it with a sigval, and read it back through a
// signalfd checking ssi_code/ssi_int; then deliver SIGUSR2 to this thread
// via rt_tgsigqueueinfo into an SA_SIGINFO handler and check the
// delivered si_value. Success token "sig2-ok".
//
// (musl's signalfd() issues signalfd4; sigqueue() issues
// rt_sigqueueinfo; rt_tgsigqueueinfo is issued raw.)
//
// Build: see REGEN_sig2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

static volatile sig_atomic_t got_usr2 = 0;
static volatile int usr2_value = 0;
static void on_usr2(int s, siginfo_t *si, void *uc) {
    (void)s; (void)uc;
    usr2_value = si->si_value.sival_int;
    got_usr2 = 1;
}

#define QVAL1 0x12345678
#define QVAL2 0x0BADF00D

int main(void) {
    // ── signalfd4 + rt_sigqueueinfo, with payload ──
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) { w("sig2-fail: block\n"); return 1; }

    int sfd = signalfd(-1, &set, 0); // -> signalfd4
    if (sfd < 0) { w("sig2-fail: signalfd\n"); return 1; }

    union sigval val;
    val.sival_int = QVAL1;
    if (sigqueue(getpid(), SIGUSR1, val) != 0) { w("sig2-fail: sigqueue\n"); return 1; }

    struct signalfd_siginfo ssi;
    memset(&ssi, 0, sizeof ssi);
    if (read(sfd, &ssi, sizeof ssi) != (ssize_t)sizeof ssi) { w("sig2-fail: sfd-read\n"); return 1; }
    if (ssi.ssi_signo != (uint32_t)SIGUSR1) { w("sig2-fail: ssi-signo\n"); return 1; }
    if (ssi.ssi_code != SI_QUEUE) { w("sig2-fail: ssi-code\n"); return 1; }
    if (ssi.ssi_int != QVAL1) { w("sig2-fail: ssi-int\n"); return 1; }
    close(sfd);

    // ── rt_tgsigqueueinfo to this thread, into an SA_SIGINFO handler ──
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr2;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) { w("sig2-fail: sigaction\n"); return 1; }

    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR2;
    si.si_code = SI_QUEUE;
    si.si_value.sival_int = QVAL2;
    long tid = syscall(SYS_gettid);
    if (syscall(SYS_rt_tgsigqueueinfo, (long)getpid(), tid, (long)SIGUSR2, &si) != 0) {
        w("sig2-fail: tgsigqueue\n"); return 1;
    }
    for (int i = 0; i < 200 && !got_usr2; i++) {
        pause();
    }
    if (!got_usr2) { w("sig2-fail: no-usr2\n"); return 1; }
    if (usr2_value != QVAL2) { w("sig2-fail: si-value\n"); return 1; }

    w("sig2-ok\n");
    return 0;
}
