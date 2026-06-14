// Signal-delivery smoke. Linux delivers a pending, unblocked signal at the
// next return-to-userspace, so the *correct* way to wait for a self-sent
// signal is the block → raise → sigsuspend idiom: block SIGUSR1, raise it
// (it stays pending while blocked), then sigsuspend with a mask that
// unblocks SIGUSR1 — sigsuspend atomically unblocks + waits, so the handler
// runs during the wait and sigsuspend returns -1/EINTR. The old
// `tkill(self); pause()` idiom races (the signal is delivered before pause)
// and hangs on real Linux too; NARF now matches Linux's deliver-on-return.
// Success token "signal-ok".
//
// Build: see REGEN_signal_smoke.sh (musl-gcc, static-PIE).
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

static void w(const char *msg) { write(1, msg, strlen(msg)); }

volatile sig_atomic_t got_signal = 0;

void handler(int sig) {
    got_signal = 1;
    write(1, "in-handler\n", 11);
    syscall(301, 76, sig); // beacon::paint(76, sig)
}

int main(void) {
    // Block SIGUSR1 so the raise below stays pending instead of being
    // delivered immediately on the tkill return.
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &block, &old) != 0) { w("signal-fail: block\n"); return 1; }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) { w("signal-fail: sigaction\n"); return 1; }

    w("signal-raise...\n");
    long tid = syscall(186);                    // gettid
    int res = (int)syscall(200, tid, SIGUSR1);  // tkill — pending while blocked
    if (res != 0) {
        char fail_msg[64];
        snprintf(fail_msg, sizeof(fail_msg), "signal-fail: tkill returned %d, errno=%d\n", res, errno);
        w(fail_msg);
        return 1;
    }
    w("tkill-ok, suspending...\n");

    // Atomically unblock SIGUSR1 (via `old`) and wait. The pending SIGUSR1
    // is delivered now, the handler runs, and sigsuspend returns -1/EINTR.
    sigsuspend(&old);
    w("suspend-returned\n");

    if (got_signal) {
        w("signal-ok\n");
    } else {
        w("signal-fail: suspend returned without signal\n");
    }
    return 0;
}
