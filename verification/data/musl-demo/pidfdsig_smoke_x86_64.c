// pidfd_send_signal(2) smoke. Open a pidfd for our own process,
// install a SIGUSR1 handler, then deliver SIGUSR1 via the pidfd and
// confirm the handler ran. Exercises the pidfd->pid resolution + the
// shared signal-delivery path. Success token "pidfdsig-ok".
//
// Build: see REGEN_pidfdsig_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>
#include <string.h>

static volatile sig_atomic_t got = 0;

static void w(const char *m) { write(1, m, strlen(m)); }
static void handler(int s) {
    (void)s;
    got = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sigaction(SIGUSR1, &sa, NULL);

    int pfd = syscall(SYS_pidfd_open, getpid(), 0);
    if (pfd < 0) {
        w("pidfdsig-fail: open\n");
        return 1;
    }
    if (syscall(SYS_pidfd_send_signal, pfd, SIGUSR1, NULL, 0) != 0) {
        w("pidfdsig-fail: send\n");
        return 1;
    }
    // The handler is dispatched on a return-to-user transition; spin a
    // few yields to give it a chance.
    for (int i = 0; i < 1000 && !got; i++) {
        sched_yield();
    }
    if (got) {
        w("pidfdsig-ok\n");
    } else {
        w("pidfdsig-fail: nodeliver\n");
    }
    return 0;
}
