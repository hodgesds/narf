// Pipe hangup-on-writer-EXIT smoke. When the last writer of a pipe goes
// away, the read end must report end-of-file to a waiter: poll(2)/epoll(7)
// wake with POLLHUP (and/or POLLIN), and read(2) returns 0.
//
// The subtlety this pins: the writer here NEVER calls close(2) on its end.
// It just _exit()s, so the only thing that can drop the write end is the
// kernel's fd-table teardown at process exit. A close()-driven hangup can
// work while an exit-driven one does not.
//
// This is how dbus-daemon learns an activated service died. It spawns a
// babysitter with an "error pipe"; the babysitter reports the child's exit
// status over a socketpair and then exits WITHOUT closing the error pipe.
// dbus waits for EPOLLHUP on that pipe to finalise the activation. Without
// the hangup it sits in epoll_wait until the 120s service_start_timeout, so
// every failed D-Bus activation costs two minutes — which is what stalled
// the KDE Plasma session on NARF.
//
// Success token "pipehup-ok".
//
// Build: see REGEN_pipehup_smoke.sh (musl-gcc, PIE).
#define _GNU_SOURCE 1
#include <sys/epoll.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // ── 1) poll(2) must see the hangup ────────────────────────────────
    int p[2];
    if (pipe(p) != 0) {
        w("pipehup-fail: pipe\n");
        return 1;
    }
    pid_t c = fork();
    if (c < 0) {
        w("pipehup-fail: fork\n");
        return 1;
    }
    if (c == 0) {
        close(p[0]);
        // Deliberately NO close(p[1]) — exit-time teardown must drop it.
        _exit(0);
    }
    close(p[1]); // parent drops its own writer copy; the child's is the last

    struct pollfd pfd = { .fd = p[0], .events = POLLIN };
    int r = poll(&pfd, 1, 10000);
    if (r <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) {
        w("pipehup-fail: poll never saw the writer's exit\n");
        return 1;
    }
    char b[8];
    if (read(p[0], b, sizeof(b)) != 0) {
        w("pipehup-fail: read did not report EOF\n");
        return 1;
    }
    int st = 0;
    waitpid(c, &st, 0);
    close(p[0]);

    // ── 2) epoll(7) must agree — registered BEFORE the writer exits, so
    //       the wait has to be woken by the exit itself. This is dbus's
    //       exact wait.
    int q[2];
    if (pipe(q) != 0) {
        w("pipehup-fail: pipe2\n");
        return 1;
    }
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = q[0] };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, q[0], &ev) < 0) {
        w("pipehup-fail: epoll_ctl\n");
        return 1;
    }
    pid_t c2 = fork();
    if (c2 < 0) {
        w("pipehup-fail: fork2\n");
        return 1;
    }
    if (c2 == 0) {
        close(q[0]);
        // Let the parent park in epoll_wait first, so the hangup must WAKE
        // a blocked waiter rather than be found already pending.
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&ts, 0);
        _exit(0); // again: no close(q[1])
    }
    close(q[1]);

    struct epoll_event out[4];
    int er = epoll_wait(ep, out, 4, 15000);
    if (er <= 0) {
        w("pipehup-fail: a blocked epoll_wait was not woken by the writer's exit\n");
        return 1;
    }
    if (read(q[0], b, sizeof(b)) != 0) {
        w("pipehup-fail: read did not report EOF after epoll\n");
        return 1;
    }
    waitpid(c2, &st, 0);

    w("pipehup-ok\n");
    return 0;
}
