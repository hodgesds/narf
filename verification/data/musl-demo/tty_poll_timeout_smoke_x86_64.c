// A readiness wait on a terminal (and an inotify fd) must honour its timeout.
//
// fish 4 queries the terminal at startup (kitty keyboard protocol, XTVERSION,
// background colour, Primary Device Attributes) and then waits for the reply
// with poll([tty, inotify], 2, 10000). When the reply never comes (fish's
// config ran fastfetch, which reads the terminal's reply itself), Linux times
// out after 10 s and fish warns "could not read response to Primary Device
// Attribute query". On NARF the wait never ended, so fish sat until Ctrl-C
// typed a byte into the terminal.
//
//   fds:     pty slave (raw mode, as fish sets it), inotify, both
//   waiters: poll, ppoll, select, pselect, epoll_wait
//
// Each wait must return 0 after about its timeout. A hang is caught by
// alarm() and named: "tty-poll-timeout-fail: case=pty+inotify/poll (hung)".
// Success token "tty-poll-timeout-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_MS 300

static const char *volatile cur_case = "setup";

static void on_alarm(int sig) {
    (void)sig;
    char buf[128];
    int n = snprintf(buf, sizeof buf, "tty-poll-timeout-fail: case=%s (hung)\n", cur_case);
    write(1, buf, n);
    _exit(1);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

enum waiter { W_POLL, W_PPOLL, W_SELECT, W_PSELECT, W_EPOLL, W_COUNT };
static const char *waiter_name[] = {"poll", "ppoll", "select", "pselect", "epoll"};

static int wait_fds(enum waiter wt, const int *fds, int n) {
    switch (wt) {
    case W_POLL:
    case W_PPOLL: {
        struct pollfd p[2];
        for (int i = 0; i < n; i++)
            p[i] = (struct pollfd){fds[i], POLLIN, 0};
        if (wt == W_POLL)
            return poll(p, n, TIMEOUT_MS);
        struct timespec ts = {0, TIMEOUT_MS * 1000000L};
        return ppoll(p, n, &ts, NULL);
    }
    case W_SELECT:
    case W_PSELECT: {
        fd_set set;
        FD_ZERO(&set);
        int max = -1;
        for (int i = 0; i < n; i++) {
            FD_SET(fds[i], &set);
            if (fds[i] > max)
                max = fds[i];
        }
        if (wt == W_SELECT) {
            struct timeval tv = {0, TIMEOUT_MS * 1000};
            return select(max + 1, &set, NULL, NULL, &tv);
        }
        struct timespec ts = {0, TIMEOUT_MS * 1000000L};
        return pselect(max + 1, &set, NULL, NULL, &ts, NULL);
    }
    case W_EPOLL: {
        int ep = epoll_create1(EPOLL_CLOEXEC);
        for (int i = 0; i < n; i++) {
            struct epoll_event ev = {.events = EPOLLIN, .data.fd = fds[i]};
            epoll_ctl(ep, EPOLL_CTL_ADD, fds[i], &ev);
        }
        struct epoll_event out[2];
        int r = epoll_wait(ep, out, 2, TIMEOUT_MS);
        close(ep);
        return r;
    }
    default:
        return -1;
    }
}

int main(void) {
    signal(SIGALRM, on_alarm);

    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        write(1, "tty-poll-timeout-fail: posix_openpt\n", 36);
        return 1;
    }
    int slave = open(ptsname(master), O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        write(1, "tty-poll-timeout-fail: open slave\n", 34);
        return 1;
    }
    // fish's reader mode: no ICANON/ECHO, VMIN=1 VTIME=0.
    struct termios t;
    tcgetattr(slave, &t);
    t.c_lflag &= ~(ICANON | ECHO | IEXTEN);
    t.c_iflag &= ~(ICRNL | IXON);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(slave, TCSANOW, &t);

    // Watch a private empty directory: a shared one like /tmp gets events
    // from unrelated processes, which would make the inotify fd readable.
    char watch_dir[] = "/tmp/inowatch.XXXXXX";
    int ino = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ino < 0 || !mkdtemp(watch_dir) ||
        inotify_add_watch(ino, watch_dir, IN_MODIFY | IN_MOVED_TO) < 0) {
        write(1, "tty-poll-timeout-fail: inotify\n", 31);
        return 1;
    }

    struct {
        const char *name;
        int fds[2];
        int n;
    } sets[] = {
        {"pty", {slave, -1}, 1},
        {"inotify", {ino, -1}, 1},
        {"pty+inotify", {slave, ino}, 2},
    };

    int failed = 0;
    char name[48];
    for (unsigned s = 0; s < sizeof sets / sizeof sets[0]; s++)
        for (int wt = 0; wt < W_COUNT; wt++) {
            snprintf(name, sizeof name, "%s/%s", sets[s].name, waiter_name[wt]);
            cur_case = name;
            alarm(5);
            long t0 = now_ms();
            int r = wait_fds(wt, sets[s].fds, sets[s].n);
            long dt = now_ms() - t0;
            alarm(0);
            if (r != 0 || dt < TIMEOUT_MS - 50 || dt > 3000) {
                char buf[128];
                int k = snprintf(buf, sizeof buf,
                                 "tty-poll-timeout-fail: case=%s result=%d errno=%d after %ldms\n",
                                 name, r, r < 0 ? errno : 0, dt);
                write(1, buf, k);
                failed = 1;
            }
        }
    close(ino);
    rmdir(watch_dir);
    if (failed)
        return 1;
    write(1, "tty-poll-timeout-ok\n", 20);
    return 0;
}
