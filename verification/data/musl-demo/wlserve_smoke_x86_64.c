/* AF_UNIX server/client wake smoke in a Wayland compositor's exact shape.
 *
 * libwayland's server never blocks in accept(2) or read(2). It parks in
 * epoll_wait(-1) over a set containing the LISTENING socket plus every
 * accepted client fd, and does nothing until that one wait returns. A
 * client is the mirror: it writes its opening requests, then parks in
 * poll(-1) until the compositor's reply arrives.
 *
 * That makes two wakeups load-bearing, and BOTH are only reachable when
 * the waiter is already parked:
 *
 *   1. a connect(2) must wake a server parked on the listening fd, and
 *   2. the first bytes on the freshly accepted fd must wake the same
 *      epoll set again — the accepted fd is registered *after* the park
 *      that the connection woke, so its readiness races registration.
 *   3. the reply must wake a client parked in poll(-1).
 *
 * Miss any of them and both processes sit idle forever with no error:
 * on NARF, foot's trace stopped dead after
 *
 *     -> wl_display#1.get_registry(new id wl_registry#2)
 *     -> wl_display#1.sync(new id wl_callback#3)
 *
 * with no wl_registry.global and no wl_callback.done ever arriving, so no
 * client window was mapped and KWin composited an empty scene — a black
 * desktop with both the compositor and the shell alive and idle.
 *
 * The existing unix_epoll smoke covers a BLOCKING accept + BLOCKING read;
 * neither goes through the parked-epoll path above. This runs many short
 * rounds because the failure is intermittent — a readiness edge lost to a
 * scan/registration race shows up as a rare round, not a reproducible one.
 *
 * Success token: `wlserve-ok`.
 * Build: see REGEN_wlserve_smoke.sh (musl-gcc, PIE).
 */
#define _GNU_SOURCE 1
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

static const char *SOCKPATH = "/tmp/wlserve.sock";

/* Enough rounds to expose a rare lost edge, few enough to stay quick. */
#define ROUNDS 64

/* The client's opening burst and the server's reply, standing in for
 * get_registry/sync and the globals/done that must come back. */
static const char REQUEST[] = "get_registry\0sync";
static const char REPLY[] = "global\0done";

static void w(const char *m) { write(1, m, strlen(m)); }

static void on_alarm(int sig) {
    (void) sig;
    w("wlserve-fail: a park never woke (lost readiness edge)\n");
    _exit(1);
}

static void settle(void) {
    /* Long enough that the peer is genuinely parked inside its wait, not
     * merely on its way there — a wake that only works when readiness is
     * already pending proves nothing. */
    const struct timespec d = { .tv_sec = 0, .tv_nsec = 40 * 1000 * 1000 };
    nanosleep(&d, NULL);
}

/* ── client ─────────────────────────────────────────────────────────── */

static int client_round(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return 10;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKPATH, sizeof addr.sun_path - 1);

    /* The server is parked in epoll_wait(-1) by now: this connect is the
     * only thing that can wake it. */
    settle();
    if (connect(fd, (struct sockaddr *) &addr, sizeof addr) != 0) {
        char m[80];
        int n = snprintf(m, sizeof m, "wlserve-diag: connect errno=%d\n", errno);
        write(1, m, n > 0 ? (size_t) n : 0);
        close(fd);
        return 11;
    }

    /* Second wake: bytes on an fd the server registers only after the
     * connection woke it. */
    settle();
    if (write(fd, REQUEST, sizeof REQUEST) != (ssize_t) sizeof REQUEST) {
        close(fd);
        return 12;
    }

    /* Third wake: park BEFORE the reply can exist, as libwayland does. */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    if (poll(&pfd, 1, -1) != 1 || !(pfd.revents & POLLIN)) {
        close(fd);
        return 13;
    }
    char buf[sizeof REPLY];
    if (read(fd, buf, sizeof buf) != (ssize_t) sizeof REPLY ||
        memcmp(buf, REPLY, sizeof REPLY) != 0) {
        close(fd);
        return 14;
    }
    close(fd);
    return 0;
}

/* ── server ─────────────────────────────────────────────────────────── */

/* Wait for exactly one ready fd, parked indefinitely. */
static int wait_one(int ep, int *out_fd) {
    struct epoll_event ev;
    int n = epoll_wait(ep, &ev, 1, -1);
    if (n != 1) {
        return 0;
    }
    *out_fd = ev.data.fd;
    return 1;
}

static int server_round(int ep, int srv) {
    int ready = -1;
    if (!wait_one(ep, &ready) || ready != srv) {
        return 20;
    }
    int conn = accept(srv, NULL, NULL);
    if (conn < 0) {
        return 21;
    }
    struct epoll_event cev = { .events = EPOLLIN, .data.fd = conn };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, conn, &cev) != 0) {
        close(conn);
        return 22;
    }

    if (!wait_one(ep, &ready) || ready != conn) {
        close(conn);
        return 23;
    }
    char buf[sizeof REQUEST];
    if (read(conn, buf, sizeof buf) != (ssize_t) sizeof REQUEST ||
        memcmp(buf, REQUEST, sizeof REQUEST) != 0) {
        close(conn);
        return 24;
    }
    if (write(conn, REPLY, sizeof REPLY) != (ssize_t) sizeof REPLY) {
        close(conn);
        return 25;
    }

    epoll_ctl(ep, EPOLL_CTL_DEL, conn, NULL);
    close(conn);
    return 0;
}

int main(void) {
    signal(SIGALRM, on_alarm);
    signal(SIGPIPE, SIG_IGN);
    unlink(SOCKPATH);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        w("wlserve-fail: socket\n");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKPATH, sizeof addr.sun_path - 1);
    if (bind(srv, (struct sockaddr *) &addr, sizeof addr) != 0) {
        w("wlserve-fail: bind\n");
        return 1;
    }
    if (listen(srv, 8) != 0) {
        w("wlserve-fail: listen\n");
        return 1;
    }

    int ep = epoll_create1(0);
    struct epoll_event sev = { .events = EPOLLIN, .data.fd = srv };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, srv, &sev) != 0) {
        w("wlserve-fail: epoll setup\n");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        w("wlserve-fail: fork\n");
        return 1;
    }
    if (child == 0) {
        close(srv);
        close(ep);
        signal(SIGALRM, on_alarm);
        for (int i = 0; i < ROUNDS; i++) {
            alarm(20);
            int rc = client_round();
            if (rc != 0) {
                char m[64];
                int n = snprintf(m, sizeof m, "wlserve-fail: client %d round %d\n", rc, i);
                write(1, m, n > 0 ? (size_t) n : 0);
                _exit(1);
            }
        }
        alarm(0);
        _exit(0);
    }

    for (int i = 0; i < ROUNDS; i++) {
        alarm(20);
        int rc = server_round(ep, srv);
        if (rc != 0) {
            char m[64];
            int n = snprintf(m, sizeof m, "wlserve-fail: server %d round %d\n", rc, i);
            write(1, m, n > 0 ? (size_t) n : 0);
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            return 1;
        }
    }
    alarm(0);

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        w("wlserve-fail: client status\n");
        return 1;
    }

    close(ep);
    close(srv);
    unlink(SOCKPATH);
    w("wlserve-ok\n");
    return 0;
}
