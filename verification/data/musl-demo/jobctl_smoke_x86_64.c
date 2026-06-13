// Terminal (termios) completeness smoke. Allocate a pty, then verify the
// terminal attributes round-trip through TCGETS/TCSETS — the default is
// cooked (ICANON|ECHO), clearing them switches to raw mode and takes
// effect, and a full-struct restore preserves every field. This is what
// interactive programs (bash/vi/less) rely on to switch terminal modes.
// Success token "jobctl-ok".
//
// Build: see REGEN_jobctl_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <termios.h>

#ifndef TIOCSPTLCK
#define TIOCSPTLCK 0x40045431
#endif
#ifndef TIOCGPTN
#define TIOCGPTN 0x80045430
#endif

static void w(const char *s) { write(1, s, strlen(s)); }

int main(void) {
    int master = open("/dev/ptmx", O_RDWR);
    if (master < 0) { w("jobctl-fail: ptmx\n"); return 1; }
    int zero = 0;
    ioctl(master, TIOCSPTLCK, &zero);
    unsigned n = 0;
    ioctl(master, TIOCGPTN, &n);
    char path[32];
    snprintf(path, sizeof path, "/dev/pts/%u", n);
    int slave = open(path, O_RDWR);
    if (slave < 0) { w("jobctl-fail: pts\n"); return 1; }

    // Default attributes are cooked: ICANON + ECHO set.
    struct termios t1, t2, raw;
    if (tcgetattr(slave, &t1) != 0) { w("jobctl-fail: tcgetattr\n"); return 1; }
    if (!(t1.c_lflag & ICANON) || !(t1.c_lflag & ECHO)) { w("jobctl-fail: default\n"); return 1; }

    // Raw mode: clearing ICANON|ECHO must take effect.
    raw = t1;
    raw.c_lflag &= ~(ICANON | ECHO);
    if (tcsetattr(slave, TCSANOW, &raw) != 0) { w("jobctl-fail: tcsetattr\n"); return 1; }
    if (tcgetattr(slave, &t2) != 0) { w("jobctl-fail: reget\n"); return 1; }
    if (t2.c_lflag & (ICANON | ECHO)) { w("jobctl-fail: raw\n"); return 1; }

    // A full-struct restore must preserve every flag word.
    tcsetattr(slave, TCSANOW, &t1);
    tcgetattr(slave, &t2);
    if (t2.c_lflag != t1.c_lflag || t2.c_iflag != t1.c_iflag || t2.c_oflag != t1.c_oflag) {
        w("jobctl-fail: roundtrip\n"); return 1;
    }

    w("jobctl-ok\n");
    return 0;
}
