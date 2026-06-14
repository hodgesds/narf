/* PTY smoke for the NARF linux-compat demo.
 *
 * Exercises NARF's /dev/ptmx + /dev/pts/N + TIOCSPTLCK + TIOCGPTN +
 * round-trip read/write across the master/slave pair. This is the
 * minimum a program like `script(1)` or `expect(1)` needs to allocate
 * a pty pair; passing this case means the PTY layer is reachable from
 * stock musl + linux-compat syscalls.
 *
 * Flow (mirrors what posix_openpt + grantpt + unlockpt + ptsname + open
 * look like under glibc/musl, written out directly to keep dependencies
 * on userland headers minimal):
 *
 *   1. master = open("/dev/ptmx", O_RDWR)
 *   2. ioctl(master, TIOCSPTLCK, &0)   — clear slave lock
 *   3. ioctl(master, TIOCGPTN, &n)     — get pty number
 *   4. snprintf("/dev/pts/%u", n) + open(slave_path, O_RDWR)
 *   5. write(master, "ping\n", 5)
 *   6. read(slave, buf, sizeof buf)    — expect "ping\n" (ICANON line)
 *   7. read(master, buf, sizeof buf)   — expect "ping\n" (ECHO mirror)
 *   8. write(slave, "pong", 4)
 *   9. read(master, buf, sizeof buf)   — expect "pong"
 *  10. write(1, "pty-ok\n", 7)
 *
 * If any step fails (open returns -1, ioctl errors, read returns the
 * wrong count or wrong bytes) the program writes "pty-fail-<step>\n"
 * to stdout and exits non-zero so the run-interactive matcher sees
 * exactly which step blew up. The success token `pty-ok` is what the
 * musl-demo xtask matches on.
 *
 * Rebuild via REGEN_pty.sh in this directory (requires musl-gcc).
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* Linux ABI numbers — mirrored in filesystem/src/devfs_pty.rs. */
#ifndef TIOCSPTLCK
#define TIOCSPTLCK 0x40045431
#endif
#ifndef TIOCGPTN
#define TIOCGPTN 0x80045430
#endif

static void w(const char *s) {
    write(1, s, strlen(s));
}

static void fail(const char *step) {
    w("pty-fail-");
    w(step);
    w("\n");
}

int main(void) {
    int master = open("/dev/ptmx", O_RDWR);
    if (master < 0) {
        fail("open-ptmx");
        return 1;
    }

    int unlock = 0;
    if (ioctl(master, TIOCSPTLCK, &unlock) < 0) {
        fail("tiocsptlck");
        return 2;
    }

    unsigned int n = 0;
    if (ioctl(master, TIOCGPTN, &n) < 0) {
        fail("tiocgptn");
        return 3;
    }

    char slave_path[32];
    int sp_len = snprintf(slave_path, sizeof slave_path, "/dev/pts/%u", n);
    if (sp_len <= 0 || sp_len >= (int)sizeof slave_path) {
        fail("snprintf");
        return 4;
    }

    int slave = open(slave_path, O_RDWR);
    if (slave < 0) {
        fail("open-slave");
        return 5;
    }

    /* Master writes a complete ICANON line; slave reads it back. The
     * n_tty line discipline now also ECHOES the line back to the master
     * (default ECHO), as a real tty does — verified at the next step. */
    const char ping[] = "ping\n";
    ssize_t wn = write(master, ping, sizeof ping - 1);
    if (wn != (ssize_t)(sizeof ping - 1)) {
        fail("write-master");
        return 6;
    }

    char buf[16] = {0};
    ssize_t rn = read(slave, buf, sizeof buf);
    if (rn != (ssize_t)(sizeof ping - 1) || memcmp(buf, ping, sizeof ping - 1) != 0) {
        fail("read-slave");
        return 7;
    }

    /* ECHO: the master sees "ping\n" mirrored back by the line discipline.
     * Drain it before the pong exchange below so the master read there is
     * unambiguous. */
    char echo[16] = {0};
    rn = read(master, echo, sizeof echo);
    if (rn != (ssize_t)(sizeof ping - 1) || memcmp(echo, ping, sizeof ping - 1) != 0) {
        fail("read-echo");
        return 8;
    }

    /* Slave writes; master reads (raw on master side). */
    const char pong[] = "pong";
    wn = write(slave, pong, sizeof pong - 1);
    if (wn != (ssize_t)(sizeof pong - 1)) {
        fail("write-slave");
        return 9;
    }

    char buf2[16] = {0};
    rn = read(master, buf2, sizeof buf2);
    if (rn != (ssize_t)(sizeof pong - 1) || memcmp(buf2, pong, sizeof pong - 1) != 0) {
        fail("read-master");
        return 10;
    }

    w("pty-ok\n");
    close(slave);
    close(master);
    return 0;
}
