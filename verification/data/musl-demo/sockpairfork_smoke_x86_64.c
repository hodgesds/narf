// socketpair(2)-across-fork(2) smoke. `sockpair_smoke` only round-trips
// bytes inside ONE process, which leaves the case every service manager
// actually depends on untested: create a pair, fork, and have the child
// write while the PARENT waits for readiness with poll(2)/epoll(7) before
// reading.
//
// This is dbus-daemon's babysitter protocol in miniature. dbus forks a
// babysitter, the babysitter forks the service and reports its exit status
// back over a socketpair, and dbus-daemon sits in epoll_wait for that
// report. If a child's write never makes the parent's end readable, every
// D-Bus service activation hangs forever — which is what wedged the KDE
// Plasma session on NARF.
//
// Success token "sockpairfork-ok".
//
// Build: see REGEN_sockpairfork_smoke.sh (musl-gcc, PIE).
#define _GNU_SOURCE 1
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        w("sockpairfork-fail: create\n");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        w("sockpairfork-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        // Child: keep sv[1], report over it, exit.
        close(sv[0]);
        if (write(sv[1], "abcd", 4) != 4) {
            _exit(2);
        }
        _exit(0);
    }

    // Parent: keep sv[0]. The child's write must make it readable.
    close(sv[1]);

    // 1) poll(2) must report POLLIN within the timeout.
    struct pollfd pfd = { .fd = sv[0], .events = POLLIN };
    int pr = poll(&pfd, 1, 10000);
    if (pr <= 0 || !(pfd.revents & POLLIN)) {
        w("sockpairfork-fail: poll saw no POLLIN from the child's write\n");
        return 1;
    }

    // 2) epoll(7) must agree — this is the exact wait dbus-daemon uses.
    int ep = epoll_create1(0);
    if (ep < 0) {
        w("sockpairfork-fail: epoll_create1\n");
        return 1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = sv[0] };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) < 0) {
        w("sockpairfork-fail: epoll_ctl\n");
        return 1;
    }
    struct epoll_event out[4];
    int er = epoll_wait(ep, out, 4, 10000);
    if (er <= 0) {
        w("sockpairfork-fail: epoll_wait saw no event from the child's write\n");
        return 1;
    }

    // 3) The bytes themselves survive the fork.
    char buf[8];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(sv[0], buf, 4);
    if (n != 4 || memcmp(buf, "abcd", 4) != 0) {
        w("sockpairfork-fail: payload wrong\n");
        return 1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        w("sockpairfork-fail: child status\n");
        return 1;
    }

    w("sockpairfork-ok\n");
    return 0;
}
