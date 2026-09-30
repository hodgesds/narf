// A connect() to a listening AF_UNIX socket must wake a poller on it.
//
// kwin starts Xwayland on demand: it listens on the X11 sockets itself
// (/tmp/.X11-unix/X0 and the abstract @/tmp/.X11-unix/X0 that xcb tries first)
// and spawns Xwayland when a client connects, i.e. when a listening fd in its
// poll set becomes readable. If that connect does not wake the poller, X
// clients (xrdb, xprop) wait forever and the Plasma session never finishes
// starting.
//
//   address:  filesystem path, abstract namespace
//   waiter:   poll, ppoll, epoll_wait, with the listener among other fds
//   client:   another process, connect() only (no data), or connect()+write
//   timing:   connect before the waiter parks or while it is parked
//
// Success token "unix-listen-wake-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 10

static int make_addr(int abstract, const char *name, struct sockaddr_un *a) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(name);
    if (abstract) {
        a->sun_path[0] = 0;
        memcpy(a->sun_path + 1, name, n);
        return (int)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
    }
    memcpy(a->sun_path, name, n + 1);
    return (int)(offsetof(struct sockaddr_un, sun_path) + n + 1);
}

// Wait up to 2 s for `lfd` (with two idle fds alongside) to be readable.
static int wait_listener(int how, int lfd, int idle1, int idle2) {
    if (how == 0 || how == 1) {
        struct pollfd p[3] = {{idle1, POLLIN, 0}, {lfd, POLLIN, 0}, {idle2, POLLIN, 0}};
        int r;
        if (how == 0) {
            r = poll(p, 3, 2000);
        } else {
            struct timespec ts = {2, 0};
            r = ppoll(p, 3, &ts, NULL);
        }
        return r >= 1 && (p[1].revents & POLLIN);
    }
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int fds[3] = {idle1, lfd, idle2};
    for (int i = 0; i < 3; i++) {
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = fds[i]};
        epoll_ctl(ep, EPOLL_CTL_ADD, fds[i], &ev);
    }
    struct epoll_event out[3];
    int r = epoll_wait(ep, out, 3, 2000);
    close(ep);
    for (int i = 0; i < r; i++)
        if (out[i].data.fd == lfd)
            return 1;
    return 0;
}

int main(void) {
    static const char *how_name[] = {"poll", "ppoll", "epoll"};
    int failed = 0;
    char path[64];
    snprintf(path, sizeof path, "/tmp/ulw-%d.sock", (int)getpid());
    int idle[2], idle2[2];
    if (pipe(idle) != 0 || pipe(idle2) != 0)
        return 1;

    for (int abstract = 0; abstract < 2; abstract++)
        for (int how = 0; how < 3; how++)
            for (int with_data = 0; with_data < 2; with_data++) {
                struct sockaddr_un a;
                char name[128];
                snprintf(name, sizeof name, "%s%s", abstract ? "ulw-abs-" : "", path);
                if (!abstract)
                    unlink(path);
                int alen = make_addr(abstract, abstract ? name : path, &a);
                int l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                if (l < 0 || bind(l, (struct sockaddr *)&a, alen) != 0 || listen(l, 16) != 0) {
                    printf("unix-listen-wake-fail: setup errno=%d\n", errno);
                    return 1;
                }
                for (int r = 0; r < ROUNDS; r++) {
                    int delay_us = (r % 2) ? 20000 : 0;
                    pid_t c = fork();
                    if (c == 0) {
                        if (delay_us)
                            usleep(delay_us);
                        int s = socket(AF_UNIX, SOCK_STREAM, 0);
                        if (connect(s, (struct sockaddr *)&a, alen) != 0)
                            _exit(2);
                        if (with_data)
                            (void)send(s, "x", 1, MSG_NOSIGNAL);
                        usleep(300000); // keep the connection open while polled
                        _exit(0);
                    }
                    int ok = wait_listener(how, l, idle[0], idle2[0]);
                    int s = accept4(l, NULL, NULL, SOCK_CLOEXEC);
                    if (s >= 0)
                        close(s);
                    int st = 0;
                    waitpid(c, &st, 0);
                    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                        printf("unix-listen-wake-fail: case=%s/%s/%s round=%d (client connect failed, status %#x)\n",
                               abstract ? "abstract" : "path", how_name[how],
                               with_data ? "connect+write" : "connect-only", r, st);
                        failed = 1;
                        break;
                    }
                    if (!ok) {
                        printf("unix-listen-wake-fail: case=%s/%s/%s round=%d (listener never became readable)\n",
                               abstract ? "abstract" : "path", how_name[how],
                               with_data ? "connect+write" : "connect-only", r);
                        failed = 1;
                        break;
                    }
                }
                close(l);
                if (!abstract)
                    unlink(path);
            }
    if (failed)
        return 1;
    printf("unix-listen-wake-ok\n");
    return 0;
}
