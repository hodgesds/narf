// epoll wakes an X server's clients exactly the way os/ospoll.c arms them.
//
// Xwayland answered every client slowly on NARF (xprop took seconds; fish,
// whose done.fish runs `xprop -root _NET_ACTIVE_WINDOW` after every command,
// stalled on each prompt). The X server's epoll use is specific:
//
//   - a client fd is added with EPOLL_CTL_ADD and an EMPTY event mask (only
//     EPOLLET: ospoll_add(..., ospoll_trigger_edge, ...) in os/connection.c),
//     then ospoll_listen() turns EPOLLIN on with EPOLL_CTL_MOD;
//   - while a reply is pending it MODs EPOLLOUT on and off again;
//   - the listening sockets are added the same way, level-triggered;
//   - it reads each client until EAGAIN before waiting again (edge mode).
//
// A server built that way must be woken promptly by a peer process's
// connect() and by every request, for many rounds. Xwayland waits with a
// finite timeout, so a missed wake shows up as latency rather than a hang:
// each round trip here must complete in well under 200 ms (microseconds on
// Linux).
//
// Success token "xserver-epoll-wake-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 40
#define LIMIT_MS 200

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ospoll_add(): EPOLL_CTL_ADD with no events, then ospoll_listen(READ).
static int ospoll_add_listen(int ep, int fd, int edge) {
    struct epoll_event ev = {.events = edge ? EPOLLET : 0, .data.fd = fd};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0)
        return -1;
    ev.events = EPOLLIN | (edge ? EPOLLET : 0);
    return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
}

// Wait (with Xwayland-like finite timeouts) until `fd` is reported readable;
// returns the elapsed ms, or -1 if it never is within 2 s.
static long wait_readable(int ep, int fd) {
    long start = now_ms();
    while (now_ms() - start < 2000) {
        struct epoll_event out[8];
        int n = epoll_wait(ep, out, 8, 560);
        for (int i = 0; i < n; i++)
            if (out[i].data.fd == fd && (out[i].events & EPOLLIN))
                return now_ms() - start;
    }
    return -1;
}

static int run(int abstract) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    char name[64];
    snprintf(name, sizeof name, "/tmp/xepw-%d-%d", (int)getpid(), abstract);
    socklen_t alen;
    if (abstract) {
        memcpy(a.sun_path + 1, name, strlen(name));
        alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name));
    } else {
        unlink(name);
        strcpy(a.sun_path, name);
        alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(name) + 1);
    }
    int l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (l < 0 || bind(l, (struct sockaddr *)&a, alen) != 0 || listen(l, 16) != 0) {
        printf("xserver-epoll-wake-fail: listener setup errno=%d\n", errno);
        return 1;
    }
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ospoll_add_listen(ep, l, 0) != 0) {
        printf("xserver-epoll-wake-fail: listener epoll setup errno=%d\n", errno);
        return 1;
    }

    pid_t c = fork();
    if (c == 0) {
        usleep(50000); // let the server park first
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *)&a, alen) != 0)
            _exit(2);
        char buf[64];
        for (int r = 0; r < ROUNDS; r++) {
            usleep(r % 2 ? 10000 : 0);
            if (write(s, "request", 7) != 7)
                _exit(3);
            if (read(s, buf, sizeof buf) <= 0)
                _exit(4);
        }
        _exit(0);
    }

    int bad = 0;
    long t = wait_readable(ep, l);
    int s = accept4(l, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (t < 0 || t > LIMIT_MS + 50 || s < 0) {
        printf("xserver-epoll-wake-fail: %s connect woke the listener after %ld ms\n",
               abstract ? "abstract" : "path", t);
        bad = 1;
    }
    if (s >= 0 && ospoll_add_listen(ep, s, 1) != 0) {
        printf("xserver-epoll-wake-fail: client epoll setup errno=%d\n", errno);
        bad = 1;
    }
    for (int r = 0; !bad && r < ROUNDS; r++) {
        long w = wait_readable(ep, s);
        if (w < 0 || w > LIMIT_MS) {
            printf("xserver-epoll-wake-fail: %s round %d request woke the server after %ld ms\n",
                   abstract ? "abstract" : "path", r, w);
            bad = 1;
            break;
        }
        // Edge mode: drain to EAGAIN, as ReadRequestFromClient does.
        char buf[64];
        while (read(s, buf, sizeof buf) > 0)
            ;
        // A pending reply: listen for write, write it, then mute write again.
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLET, .data.fd = s};
        epoll_ctl(ep, EPOLL_CTL_MOD, s, &ev);
        if (write(s, "reply", 5) != 5) {
            printf("xserver-epoll-wake-fail: reply write errno=%d\n", errno);
            bad = 1;
            break;
        }
        ev.events = EPOLLIN | EPOLLET;
        epoll_ctl(ep, EPOLL_CTL_MOD, s, &ev);
    }
    int st = 0;
    if (bad)
        kill(c, 9);
    waitpid(c, &st, 0);
    if (!bad && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
        printf("xserver-epoll-wake-fail: client status %#x\n", st);
        bad = 1;
    }
    close(s);
    close(l);
    close(ep);
    if (!abstract)
        unlink(name);
    return bad;
}

int main(void) {
    int failed = run(0) | run(1);
    if (failed)
        return 1;
    printf("xserver-epoll-wake-ok\n");
    return 0;
}
