// Console-is-a-tty smoke. stdin (fd 0) must look like a real terminal so
// an interactive shell draws a prompt and line-edits: isatty(0) true,
// tcgetattr returns a cooked-mode termios (ICANON|ECHO set), and
// tcsetattr round-trips a raw-mode switch (vi/less/readline rely on
// this). Success token "consoletty-ok".
//
// Build: see REGEN_consoletty_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <termios.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    if (!isatty(0)) {
        w("consoletty-fail: isatty\n");
        return 1;
    }
    struct termios t, t2;
    memset(&t, 0, sizeof t);
    memset(&t2, 0, sizeof t2);
    if (tcgetattr(0, &t) != 0) {
        w("consoletty-fail: tcgetattr\n");
        return 1;
    }
    if (!(t.c_lflag & ICANON) || !(t.c_lflag & ECHO)) {
        w("consoletty-fail: not-cooked\n");
        return 1;
    }
    // Switch to raw and confirm it round-trips.
    struct termios raw = t;
    raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
    if (tcsetattr(0, TCSANOW, &raw) != 0) {
        w("consoletty-fail: tcsetattr\n");
        return 1;
    }
    if (tcgetattr(0, &t2) != 0 || (t2.c_lflag & (ICANON | ECHO))) {
        w("consoletty-fail: roundtrip\n");
        return 1;
    }
    // Restore cooked so we don't leave the shared console in raw mode.
    tcsetattr(0, TCSANOW, &t);
    w("consoletty-ok\n");
    return 0;
}
