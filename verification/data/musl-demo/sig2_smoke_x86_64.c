// Signal-queueing smoke: signalfd4 + rt_sigqueueinfo + rt_tgsigqueueinfo.
// Block SIGUSR1, read a queued instance back through a signalfd, then
// deliver SIGUSR2 to this thread via rt_tgsigqueueinfo and catch it.
// Success token "sig2-ok".
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
static void on_usr2(int s) { (void)s; got_usr2 = 1; }

int main(void) {
    // ── signalfd4 + rt_sigqueueinfo ──
    // Block SIGUSR1 so a queued instance stays pending for the signalfd
    // to drain (rather than being delivered).
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) { w("sig2-fail: block\n"); return 1; }

    int sfd = signalfd(-1, &set, 0); // -> signalfd4
    if (sfd < 0) { w("sig2-fail: signalfd\n"); return 1; }

    union sigval val;
    val.sival_int = 0;
    if (sigqueue(getpid(), SIGUSR1, val) != 0) { w("sig2-fail: sigqueue\n"); return 1; }

    struct signalfd_siginfo ssi;
    memset(&ssi, 0, sizeof ssi);
    if (read(sfd, &ssi, sizeof ssi) != (ssize_t)sizeof ssi) { w("sig2-fail: sfd-read\n"); return 1; }
    if (ssi.ssi_signo != (uint32_t)SIGUSR1) { w("sig2-fail: ssi-signo\n"); return 1; }
    close(sfd);

    // ── rt_tgsigqueueinfo to this thread ──
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr2;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) { w("sig2-fail: sigaction\n"); return 1; }

    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR2;
    si.si_code = -1; // SI_QUEUE
    long tid = syscall(SYS_gettid);
    if (syscall(SYS_rt_tgsigqueueinfo, (long)getpid(), tid, (long)SIGUSR2, &si) != 0) {
        w("sig2-fail: tgsigqueue\n"); return 1;
    }
    for (int i = 0; i < 200 && !got_usr2; i++) {
        pause();
    }
    if (!got_usr2) { w("sig2-fail: no-usr2\n"); return 1; }

    w("sig2-ok\n");
    return 0;
}
