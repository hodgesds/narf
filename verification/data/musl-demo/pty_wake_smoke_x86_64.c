// A write to one side of a pty must wake a reader parked on the other side.
//
// fish writes its terminal queries to the pty slave and waits for konsole's
// reply; konsole waits for output on the pty master (Qt's poll loop). On NARF
// the slave write did not wake the master's poller, so konsole never saw the
// query and never answered, and fish waited until Ctrl-C (a keypress that
// woke konsole, which then drained the queued query and replied).
//
//   directions: slave write -> master reader (terminal output, konsole's side)
//               master write -> slave reader (terminal input, fish's side)
//   writers:    another thread, another process
//   slave mode: canonical, raw (fish's reader mode)
//   waiters:    poll, ppoll, select, epoll_wait
//   extra fd:   none, or an idle inotify fd in the same wait set (fish's
//               poll([tty, inotify], 2, 10000) shape)
//   timing:     the write lands before the waiter parks or while it is parked
//
// Every wait has a 2 s timeout, so a lost wake reports e.g.
// "pty-wake-fail: case=slave->master/raw/thread/poll round=5 result=0".
// Success token "pty-wake-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 20
#define TIMEOUT_MS 2000

enum waiter { W_POLL, W_PPOLL, W_SELECT, W_EPOLL, W_COUNT };
static const char *waiter_name[] = {"poll", "ppoll", "select", "epoll"};

// Wait for `fd` to become readable; `extra` (-1 for none) is an idle fd in
// the same wait set.
static int wait_readable(enum waiter wt, int fd, int extra) {
    int n = extra >= 0 ? 2 : 1;
    switch (wt) {
    case W_POLL:
    case W_PPOLL: {
        struct pollfd p[2] = {{fd, POLLIN, 0}, {extra, POLLIN, 0}};
        int r;
        if (wt == W_POLL) {
            r = poll(p, n, TIMEOUT_MS);
        } else {
            struct timespec ts = {TIMEOUT_MS / 1000, 0};
            r = ppoll(p, n, &ts, NULL);
        }
        return r < 0 ? -1 : (r == 1 && (p[0].revents & POLLIN));
    }
    case W_SELECT: {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        int max = fd;
        if (extra >= 0) {
            FD_SET(extra, &set);
            if (extra > max)
                max = extra;
        }
        struct timeval tv = {TIMEOUT_MS / 1000, 0};
        int r = select(max + 1, &set, NULL, NULL, &tv);
        return r < 0 ? -1 : (r == 1 && FD_ISSET(fd, &set));
    }
    case W_EPOLL: {
        int ep = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
        if (extra >= 0) {
            struct epoll_event ev2 = {.events = EPOLLIN, .data.fd = extra};
            epoll_ctl(ep, EPOLL_CTL_ADD, extra, &ev2);
        }
        struct epoll_event out[2];
        int r = epoll_wait(ep, out, 2, TIMEOUT_MS);
        close(ep);
        return r < 0 ? -1 : (r == 1 && out[0].data.fd == fd);
    }
    default:
        return -1;
    }
}

struct writer_args {
    int fd;
    int delay_us;
};

static void do_write(int fd, int delay_us) {
    if (delay_us) {
        struct timespec ts = {0, delay_us * 1000L};
        nanosleep(&ts, NULL);
    }
    // A query-sized write ending in a newline, so a canonical reader sees a
    // complete line.
    (void)write(fd, "\x1b[c\n", 4);
}

static void *writer_thread(void *p) {
    struct writer_args *a = p;
    do_write(a->fd, a->delay_us);
    return NULL;
}

static void drain(int fd) {
    char buf[256];
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    while (read(fd, buf, sizeof buf) > 0)
        ;
    fcntl(fd, F_SETFL, fl);
}

static int open_pty(int raw, int *master, int *slave) {
    *master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (*master < 0 || grantpt(*master) != 0 || unlockpt(*master) != 0)
        return -1;
    *slave = open(ptsname(*master), O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (*slave < 0)
        return -1;
    struct termios t;
    tcgetattr(*slave, &t);
    t.c_lflag &= ~ECHO; // keep the master side quiet for slave-reader cases
    if (raw) {
        t.c_lflag &= ~(ICANON | IEXTEN);
        t.c_iflag &= ~(ICRNL | IXON);
        t.c_oflag &= ~OPOST;
        t.c_cc[VMIN] = 1;
        t.c_cc[VTIME] = 0;
    }
    tcsetattr(*slave, TCSANOW, &t);
    return 0;
}

int main(void) {
    int failed = 0;
    // Watch a private empty directory: a shared one like /tmp gets events
    // from unrelated processes, which would make the inotify fd readable.
    char watch_dir[] = "/tmp/inowatch.XXXXXX";
    int ino = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ino < 0 || !mkdtemp(watch_dir) ||
        inotify_add_watch(ino, watch_dir, IN_MODIFY | IN_MOVED_TO) < 0) {
        printf("pty-wake-fail: inotify setup errno=%d\n", errno);
        return 1;
    }
    for (int with_ino = 0; with_ino < 2; with_ino++)
    for (int dir = 0; dir < 2; dir++)          // 0: slave->master, 1: master->slave
        for (int raw = 0; raw < 2; raw++)
            for (int proc = 0; proc < 2; proc++) // 0: thread writer, 1: process writer
                for (int wt = 0; wt < W_COUNT; wt++) {
                    int master, slave;
                    if (open_pty(raw, &master, &slave) != 0) {
                        printf("pty-wake-fail: pty setup errno=%d\n", errno);
                        return 1;
                    }
                    int wfd = dir == 0 ? slave : master;
                    int rfd = dir == 0 ? master : slave;
                    for (int r = 0; r < ROUNDS; r++) {
                        int delay = (r % 4) * 1000;
                        pthread_t t;
                        struct writer_args a = {wfd, delay};
                        pid_t child = -1;
                        if (proc) {
                            child = fork();
                            if (child == 0) {
                                do_write(wfd, delay);
                                _exit(0);
                            }
                        } else {
                            pthread_create(&t, NULL, writer_thread, &a);
                        }
                        int got = wait_readable(wt, rfd, with_ino ? ino : -1);
                        if (proc)
                            waitpid(child, NULL, 0);
                        else
                            pthread_join(t, NULL);
                        if (got != 1) {
                            printf("pty-wake-fail: case=%s%s/%s/%s/%s round=%d result=%d\n",
                                   dir == 0 ? "slave->master" : "master->slave",
                                   with_ino ? "+inotify" : "",
                                   raw ? "raw" : "canon", proc ? "process" : "thread",
                                   waiter_name[wt], r, got);
                            fflush(stdout);
                            failed = 1;
                            break;
                        }
                        drain(rfd);
                    }
                    close(slave);
                    close(master);
                }
    close(ino);
    rmdir(watch_dir);
    if (failed)
        return 1;
    printf("pty-wake-ok\n");
    return 0;
}
