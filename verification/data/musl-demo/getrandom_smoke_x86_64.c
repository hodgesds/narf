// getrandom(2) smoke. Exercises the getrandom syscall end-to-end via
// a real musl binary: fill a buffer and verify the full length came
// back with some non-zero entropy. Uses the raw syscall() form so the
// test doesn't depend on the musl <sys/random.h> wrapper version.
// Success token "getrandom-ok".
//
// Build: see REGEN_getrandom_smoke.sh (musl-gcc, static-PIE).
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    unsigned char buf[16];
    memset(buf, 0, sizeof buf);
    long n = syscall(SYS_getrandom, buf, sizeof buf, 0);
    if (n != (long)sizeof buf) {
        w("getrandom-fail: short\n");
        return 1;
    }
    int nonzero = 0;
    for (unsigned i = 0; i < sizeof buf; i++) {
        if (buf[i] != 0) {
            nonzero = 1;
        }
    }
    if (nonzero) {
        w("getrandom-ok\n");
    } else {
        w("getrandom-fail: all-zero\n");
    }
    return 0;
}
