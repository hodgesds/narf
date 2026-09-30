// TIOCGPTPEER opens a pty master's slave, as openpty() and sudo's use_pty do.
//
// sudo 1.9 runs commands in a new pty by default (use_pty) and gets it from
// openpty(), which asks the master for its slave with
// ioctl(master, TIOCGPTPEER, O_RDWR|O_NOCTTY) — Linux 4.13+,
// drivers/tty/pty.c::ptm_open_peer. NARF matched the request against
// 0x40045441 instead of Linux's `_IO('T', 0x41)` = 0x5441, so every real
// caller got "Operation not supported" ("sudo: unable to allocate pty").
//
//   - ioctl(master, TIOCGPTPEER, O_RDWR|O_NOCTTY|O_CLOEXEC) returns the slave:
//     its rdev minor is the master's TIOCGPTN, it is O_RDWR, FD_CLOEXEC is
//     set, and bytes written to the master arrive on it;
//   - O_NONBLOCK in the flags lands on the new description;
//   - TIOCGPTPEER on a slave (not a master) is EIO (ptm_open_peer:
//     `if (tty->driver != ptm_driver) return -EIO;`);
//   - openpty() succeeds and returns a connected pair.
//
// Success token "tiocgptpeer-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <unistd.h>
#include <pty.h>

#ifndef TIOCGPTPEER
#define TIOCGPTPEER 0x5441
#endif

static int failed;

static void fail(const char *what, long v) {
    printf("tiocgptpeer-fail: %s (%ld)\n", what, v);
    failed = 1;
}

static int raw_pair_ok(int m, int s) {
    struct termios t;
    if (tcgetattr(s, &t) == 0) {
        cfmakeraw(&t);
        tcsetattr(s, TCSANOW, &t);
    }
    if (write(m, "abc", 3) != 3)
        return 0;
    char b[8];
    return read(s, b, sizeof b) == 3 && memcmp(b, "abc", 3) == 0;
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) {
        printf("tiocgptpeer-fail: pty setup errno=%d\n", errno);
        return 1;
    }
    unsigned ptn = 0;
    if (ioctl(m, TIOCGPTN, &ptn) != 0)
        fail("TIOCGPTN errno", errno);

    int s = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (s < 0) {
        fail("TIOCGPTPEER on the master errno", errno);
    } else {
        struct stat st;
        if (fstat(s, &st) != 0 || !S_ISCHR(st.st_mode) || minor(st.st_rdev) != ptn)
            fail("the peer is not the master's slave (minor)", (long)minor(st.st_rdev));
        if ((fcntl(s, F_GETFL) & O_ACCMODE) != O_RDWR)
            fail("the peer is not O_RDWR", fcntl(s, F_GETFL));
        if (!(fcntl(s, F_GETFD) & FD_CLOEXEC))
            fail("O_CLOEXEC did not set FD_CLOEXEC", 0);
        if (!raw_pair_ok(m, s))
            fail("master bytes did not reach the peer", errno);
        // TIOCGPTPEER on a slave: ptm_open_peer refuses a non-master with EIO.
        if (ioctl(s, TIOCGPTPEER, O_RDWR) != -1 || errno != EIO)
            fail("TIOCGPTPEER on a slave was not EIO, errno", errno);
        close(s);
    }
    int n = ioctl(m, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (n < 0)
        fail("TIOCGPTPEER with O_NONBLOCK errno", errno);
    else if (!(fcntl(n, F_GETFL) & O_NONBLOCK))
        fail("O_NONBLOCK did not reach the peer description", 0);
    if (n >= 0)
        close(n);
    close(m);

    int am, as;
    char name[64];
    if (openpty(&am, &as, name, NULL, NULL) != 0)
        fail("openpty errno", errno);
    else if (!raw_pair_ok(am, as))
        fail("openpty pair is not connected", errno);

    if (failed)
        return 1;
    printf("tiocgptpeer-ok\n");
    return 0;
}
