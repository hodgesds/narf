// preadv(2) + pwritev(2) smoke. Write two iovecs to a memfd at an
// explicit offset with pwritev, then read them back into two iovecs at
// the same offset with preadv. Success token "pv-ok".
//
// Build: see REGEN_pv_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = memfd_create("pv", 0);
    if (fd < 0) {
        w("pv-fail: memfd\n");
        return 1;
    }

    char a[5] = {'h', 'e', 'l', 'l', 'o'}, b[5] = {'w', 'o', 'r', 'l', 'd'};
    struct iovec wv[2] = {{a, 5}, {b, 5}};
    if (pwritev(fd, wv, 2, 0) != 10) {
        w("pv-fail: pwritev\n");
        return 1;
    }

    char x[5] = {0}, y[5] = {0};
    struct iovec rv[2] = {{x, 5}, {y, 5}};
    if (preadv(fd, rv, 2, 0) != 10) {
        w("pv-fail: preadv\n");
        return 1;
    }

    if (memcmp(x, "hello", 5) == 0 && memcmp(y, "world", 5) == 0) {
        w("pv-ok\n");
    } else {
        w("pv-fail: data\n");
    }
    close(fd);
    return 0;
}
