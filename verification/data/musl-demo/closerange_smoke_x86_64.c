// close_range(2) smoke. dup() stdout to a few fds, close_range them,
// and verify they are no longer open (fcntl F_GETFD -> EBADF). Uses
// the raw syscall() form so the test doesn't depend on a musl wrapper.
// Success token "closerange-ok".
//
// Build: see REGEN_closerange_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int a = dup(1), b = dup(1), c = dup(1);
    if (a < 0 || b < 0 || c < 0) {
        w("closerange-fail: dup\n");
        return 1;
    }
    int lo = a < c ? a : c;
    int hi = a > c ? a : c;
    if (syscall(SYS_close_range, lo, hi, 0) != 0) {
        w("closerange-fail: call\n");
        return 1;
    }
    if (fcntl(a, F_GETFD) != -1 || fcntl(b, F_GETFD) != -1 ||
        fcntl(c, F_GETFD) != -1) {
        w("closerange-fail: still-open\n");
        return 1;
    }
    w("closerange-ok\n");
    return 0;
}
