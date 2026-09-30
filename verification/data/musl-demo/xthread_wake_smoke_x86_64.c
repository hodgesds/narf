// Cross-thread readiness wake matrix.
//
// A thread parked in a readiness wait must wake when ANOTHER thread makes
// its fd readable. fish's startup hang on NARF was this shape: the main
// thread waits for its I/O thread's notify (FdEventSignaller, an eventfd
// on Linux), the wake is lost, and only a signal (Ctrl-C -> EINTR ->
// re-scan) unsticks it. The pipe form was fixed earlier; this smoke covers
// the whole family so a lost wake is a named failure, not a hang.
//
//   fd kinds: eventfd, pipe, AF_UNIX socketpair
//   waiters:  poll, ppoll, select, pselect, epoll_wait
//   timing:   the writer (another thread) fires before the waiter parks or
//             while it is parked (0..3 ms delay)
//
// Every wait has a 2 s timeout, so a lost wake reports e.g.
// "xthread-wake-fail: case=eventfd/select round=17".
//
// Success token "xthread-wake-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 120
#define TIMEOUT_MS 2000

static void w(const char *m) { write(1, m, strlen(m)); }

enum kind { K_EVENTFD, K_PIPE, K_SOCKPAIR, K_COUNT };
enum waiter { W_POLL, W_PPOLL, W_SELECT, W_PSELECT, W_EPOLL, W_COUNT };
static const char *kind_name[] = {"eventfd", "pipe", "socketpair"};
static const char *waiter_name[] = {"poll", "ppoll", "select", "pselect", "epoll"};

struct wake_args {
    int wfd;
    enum kind kind;
    int delay_us;
};

static void *writer(void *p) {
    struct wake_args *a = p;
    if (a->delay_us) {
        struct timespec ts = {0, a->delay_us * 1000L};
        nanosleep(&ts, NULL);
    }
    if (a->kind == K_EVENTFD) {
        uint64_t one = 1;
        if (write(a->wfd, &one, sizeof one) != sizeof one)
            w("xthread-wake-fail: eventfd write\n");
    } else {
        if (write(a->wfd, "x", 1) != 1)
            w("xthread-wake-fail: write\n");
    }
    return NULL;
}

// Returns 1 when rfd became readable, 0 on timeout, -1 on error.
static int wait_readable(enum waiter wt, int rfd, int epfd) {
    switch (wt) {
    case W_POLL: {
        struct pollfd pfd = {rfd, POLLIN, 0};
        int r = poll(&pfd, 1, TIMEOUT_MS);
        return r < 0 ? -1 : (r == 1 && (pfd.revents & POLLIN));
    }
    case W_PPOLL: {
        struct pollfd pfd = {rfd, POLLIN, 0};
        struct timespec ts = {TIMEOUT_MS / 1000, (TIMEOUT_MS % 1000) * 1000000L};
        int r = ppoll(&pfd, 1, &ts, NULL);
        return r < 0 ? -1 : (r == 1 && (pfd.revents & POLLIN));
    }
    case W_SELECT: {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(rfd, &set);
        struct timeval tv = {TIMEOUT_MS / 1000, (TIMEOUT_MS % 1000) * 1000};
        int r = select(rfd + 1, &set, NULL, NULL, &tv);
        return r < 0 ? -1 : (r == 1 && FD_ISSET(rfd, &set));
    }
    case W_PSELECT: {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(rfd, &set);
        struct timespec ts = {TIMEOUT_MS / 1000, (TIMEOUT_MS % 1000) * 1000000L};
        int r = pselect(rfd + 1, &set, NULL, NULL, &ts, NULL);
        return r < 0 ? -1 : (r == 1 && FD_ISSET(rfd, &set));
    }
    case W_EPOLL: {
        struct epoll_event ev;
        int r = epoll_wait(epfd, &ev, 1, TIMEOUT_MS);
        return r < 0 ? -1 : r == 1;
    }
    default:
        return -1;
    }
}

static void drain(enum kind k, int rfd) {
    char buf[64];
    if (k == K_EVENTFD) {
        uint64_t v;
        (void)read(rfd, &v, sizeof v);
    } else {
        (void)read(rfd, buf, sizeof buf);
    }
}

static int run_case(enum kind k, enum waiter wt) {
    int rfd, wfd;
    int fds[2];
    if (k == K_EVENTFD) {
        rfd = wfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (rfd < 0)
            return -1;
    } else if (k == K_PIPE) {
        if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0)
            return -1;
        rfd = fds[0];
        wfd = fds[1];
    } else {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds) != 0)
            return -1;
        rfd = fds[0];
        wfd = fds[1];
    }
    int epfd = -1;
    if (wt == W_EPOLL) {
        epfd = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = rfd};
        if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, rfd, &ev) != 0)
            return -1;
    }
    int rc = 0;
    for (int r = 0; r < ROUNDS && rc == 0; r++) {
        struct wake_args a = {wfd, k, (r % 4) * 1000};
        pthread_t t;
        if (pthread_create(&t, NULL, writer, &a) != 0)
            return -1;
        int got = wait_readable(wt, rfd, epfd);
        if (got != 1) {
            char buf[96];
            int n = snprintf(buf, sizeof buf, "xthread-wake-fail: case=%s/%s round=%d result=%d\n",
                             kind_name[k], waiter_name[wt], r, got);
            write(1, buf, n);
            rc = 1;
        }
        pthread_join(t, NULL);
        drain(k, rfd);
    }
    if (epfd >= 0)
        close(epfd);
    close(rfd);
    if (wfd != rfd)
        close(wfd);
    return rc;
}

int main(void) {
    int failed = 0;
    for (int k = 0; k < K_COUNT; k++)
        for (int wt = 0; wt < W_COUNT; wt++) {
            int r = run_case(k, wt);
            if (r < 0) {
                char buf[80];
                int n = snprintf(buf, sizeof buf, "xthread-wake-fail: setup %s/%s errno=%d\n",
                                 kind_name[k], waiter_name[wt], errno);
                write(1, buf, n);
                return 1;
            }
            failed |= r;
        }
    if (failed)
        return 1;
    w("xthread-wake-ok\n");
    return 0;
}
