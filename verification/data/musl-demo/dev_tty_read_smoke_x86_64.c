// A blocking read of /dev/tty waits for input, as sudo's password prompt needs.
//
// sudo (tgetpass) and su (PAM's conversation) read the password from
// open("/dev/tty", O_RDWR). On NARF that read failed at once with EAGAIN
// ("sudo: unable to read password: Resource temporarily unavailable"; su:
// "Authentication token manipulation error"). Linux gives each open of
// /dev/tty its own struct file: O_NONBLOCK is per open file description, so
// a flag another descriptor of the same terminal carries (fish sets it on
// its stdin) never leaks into it, and tty_read blocks until a line arrives.
//
// In a child that owns a fresh pty as its controlling terminal:
//   - the pty slave fd is made O_NONBLOCK;
//   - /dev/tty is opened O_RDWR: it must not report O_NONBLOCK, and a read
//     issued before any input must block until the line arrives (parent
//     writes it 200 ms later), then return it — not EAGAIN;
//   - poll() on the /dev/tty fd must wake when a second line arrives;
//   - the O_NONBLOCK slave fd itself still reads EAGAIN when empty.
//
// Success token "dev-tty-read-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int child(const char *slave_name) {
    if (setsid() < 0)
        return 10;
    int s = open(slave_name, O_RDWR | O_NOCTTY);
    if (s < 0 || ioctl(s, TIOCSCTTY, 0) != 0)
        return 11;
    // Canonical input, no echo — what tgetpass sets before reading.
    struct termios t;
    if (tcgetattr(s, &t) != 0)
        return 12;
    t.c_lflag |= ICANON;
    t.c_lflag &= ~(ECHO | ECHONL);
    if (tcsetattr(s, TCSANOW, &t) != 0)
        return 13;
    // Another descriptor of the same terminal carries O_NONBLOCK.
    if (fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK) != 0)
        return 14;

    int tty = open("/dev/tty", O_RDWR);
    if (tty < 0) {
        printf("dev-tty-read-fail: open(/dev/tty) errno=%d\n", errno);
        return 1;
    }
    if (fcntl(tty, F_GETFL) & O_NONBLOCK) {
        printf("dev-tty-read-fail: a fresh /dev/tty open inherited O_NONBLOCK\n");
        return 1;
    }
    // Tell the parent we are about to block, then read before any input.
    kill(getppid(), SIGUSR1);
    char buf[64];
    long t0 = now_ms();
    ssize_t n = read(tty, buf, sizeof buf);
    long waited = now_ms() - t0;
    if (n < 0) {
        printf("dev-tty-read-fail: blocking read(/dev/tty) errno=%d after %ld ms\n", errno,
               waited);
        return 1;
    }
    if (n != 7 || memcmp(buf, "secret\n", 7) != 0) {
        printf("dev-tty-read-fail: read(/dev/tty) returned %zd bytes\n", n);
        return 1;
    }
    if (waited < 100) {
        printf("dev-tty-read-fail: read(/dev/tty) returned after %ld ms, before the input\n",
               waited);
        return 1;
    }
    // The O_NONBLOCK slave fd reads EAGAIN when there is nothing to read.
    if (read(s, buf, sizeof buf) != -1 || errno != EAGAIN) {
        printf("dev-tty-read-fail: O_NONBLOCK slave read did not give EAGAIN (errno=%d)\n",
               errno);
        return 1;
    }
    // poll() on /dev/tty wakes on the next line.
    kill(getppid(), SIGUSR2);
    struct pollfd p = {.fd = tty, .events = POLLIN};
    int r = poll(&p, 1, 3000);
    if (r != 1 || !(p.revents & POLLIN)) {
        printf("dev-tty-read-fail: poll(/dev/tty) r=%d revents=%#x\n", r, p.revents);
        return 1;
    }
    n = read(tty, buf, sizeof buf);
    if (n != 3 || memcmp(buf, "ok\n", 3) != 0) {
        printf("dev-tty-read-fail: second read(/dev/tty) returned %zd bytes\n", n);
        return 1;
    }
    return 0;
}

static volatile sig_atomic_t stage;
static void on_sig(int sig) { stage = sig == SIGUSR1 ? 1 : 2; }

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) != 0 || unlockpt(m) != 0) {
        printf("dev-tty-read-fail: pty setup errno=%d\n", errno);
        return 1;
    }
    char *name = ptsname(m);
    if (!name)
        return 1;
    signal(SIGUSR1, on_sig);
    signal(SIGUSR2, on_sig);
    pid_t c = fork();
    if (c == 0)
        _exit(child(name));
    long t0 = now_ms();
    while (stage < 1 && now_ms() - t0 < 5000)
        usleep(1000);
    usleep(200000); // the child is now parked in read(/dev/tty)
    if (write(m, "secret\n", 7) != 7)
        return 1;
    while (stage < 2 && now_ms() - t0 < 10000)
        usleep(1000);
    usleep(100000); // the child is now parked in poll(/dev/tty)
    if (write(m, "ok\n", 3) != 3)
        return 1;
    int st = 0;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("dev-tty-read-fail: child status %#x\n", st);
        return 1;
    }
    printf("dev-tty-read-ok\n");
    return 0;
}
