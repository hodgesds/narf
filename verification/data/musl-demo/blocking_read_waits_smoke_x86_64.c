// A blocking read() on an empty stream waits for data; only O_NONBLOCK gets EAGAIN.
//
// Linux n_tty_read, eventfd_read, timerfd_read and signalfd_read all test
// `file->f_flags & O_NONBLOCK`: without it an empty read sleeps until data
// arrives. NARF answered EAGAIN whenever the source was empty, whatever the
// description's flags, which broke every reader that read() without polling
// first — sudo's and su's password prompts ("unable to read password:
// Resource temporarily unavailable").
//
// For a pty slave, an eventfd, a timerfd and a signalfd:
//   - a blocking read issued before any data waits (>= 100 ms here) and then
//     returns the data, from another process or a timer;
//   - the same empty read on an O_NONBLOCK description returns EAGAIN.
//
// Success token "blocking-read-waits-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int failed;

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void fail(const char *what, long v) {
    printf("blocking-read-waits-fail: %s (%ld)\n", what, v);
    failed = 1;
}

// A blocking read of `fd` must wait for the data `feed` delivers later.
static void expect_wait(const char *name, int fd, void *buf, size_t len, ssize_t want) {
    // Unconditional, so a read that never returns names itself.
    printf("blocking-read-waits: %s: blocking read\n", name);
    fflush(stdout);
    long t0 = now_ms();
    ssize_t n = read(fd, buf, len);
    long waited = now_ms() - t0;
    char m[96];
    if (n < 0) {
        snprintf(m, sizeof m, "%s: blocking read failed, errno", name);
        fail(m, errno);
    } else if (n != want) {
        snprintf(m, sizeof m, "%s: blocking read returned bytes", name);
        fail(m, n);
    } else if (waited < 100) {
        snprintf(m, sizeof m, "%s: blocking read returned before the data, ms", name);
        fail(m, waited);
    }
}

static void expect_eagain(const char *name, int fd, void *buf, size_t len) {
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    ssize_t n = read(fd, buf, len);
    int e = errno;
    fcntl(fd, F_SETFL, fl);
    if (n != -1 || e != EAGAIN) {
        char m[96];
        snprintf(m, sizeof m, "%s: O_NONBLOCK empty read was not EAGAIN, errno", name);
        fail(m, n == -1 ? e : 0);
    }
}

// Fork a child that runs `feed(arg)` after 200 ms.
static pid_t later(void (*feed)(long), long arg) {
    pid_t c = fork();
    if (c == 0) {
        usleep(200000);
        feed(arg);
        _exit(0);
    }
    return c;
}

static void feed_pty(long master) { (void)write((int)master, "line\n", 5); }
static void feed_eventfd(long fd) {
    uint64_t one = 1;
    (void)write((int)fd, &one, sizeof one);
}
static void feed_signal(long pid) { kill((pid_t)pid, SIGUSR1); }

int main(void) {
    char buf[64];

    // pty slave, canonical mode, opened without O_NONBLOCK.
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) {
        printf("blocking-read-waits-fail: pty setup errno=%d\n", errno);
        return 1;
    }
    int s = open(ptsname(m), O_RDWR | O_NOCTTY);
    struct termios t;
    tcgetattr(s, &t);
    t.c_lflag |= ICANON;
    t.c_lflag &= ~(ECHO | ECHONL);
    tcsetattr(s, TCSANOW, &t);
    expect_eagain("pty slave", s, buf, sizeof buf);
    pid_t c = later(feed_pty, m);
    expect_wait("pty slave", s, buf, sizeof buf, 5);
    waitpid(c, NULL, 0);

    // eventfd.
    int efd = eventfd(0, EFD_CLOEXEC);
    uint64_t v;
    expect_eagain("eventfd", efd, &v, sizeof v);
    c = later(feed_eventfd, efd);
    expect_wait("eventfd", efd, &v, sizeof v, 8);
    waitpid(c, NULL, 0);

    // timerfd armed 200 ms out.
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    expect_eagain("timerfd", tfd, &v, sizeof v);
    struct itimerspec its = {.it_value = {0, 200000000}};
    timerfd_settime(tfd, 0, &its, NULL);
    expect_wait("timerfd", tfd, &v, sizeof v, 8);

    // signalfd for SIGUSR1, blocked.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    int sfd = signalfd(-1, &set, SFD_CLOEXEC);
    struct signalfd_siginfo si;
    expect_eagain("signalfd", sfd, &si, sizeof si);
    c = later(feed_signal, getpid());
    expect_wait("signalfd", sfd, &si, sizeof si, sizeof si);
    waitpid(c, NULL, 0);

    if (failed)
        return 1;
    printf("blocking-read-waits-ok\n");
    return 0;
}
