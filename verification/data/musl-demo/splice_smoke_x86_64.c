// splice(2) smoke. Use a memfd as the source, splice it into a pipe
// without a userspace copy, then read it back out the other end.
// Success token "splice-ok".
//
// Build: see REGEN_splice_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int mfd = memfd_create("sp", 0);
    if (mfd < 0) {
        w("splice-fail: memfd\n");
        return 1;
    }
    const char *data = "splice-payload";
    size_t n = strlen(data);
    if (write(mfd, data, n) != (ssize_t)n) {
        w("splice-fail: write\n");
        return 1;
    }
    lseek(mfd, 0, SEEK_SET);

    int pf[2];
    if (pipe(pf) < 0) {
        w("splice-fail: pipe\n");
        return 1;
    }
    ssize_t s = splice(mfd, NULL, pf[1], NULL, n, 0);
    if (s != (ssize_t)n) {
        w("splice-fail: splice\n");
        return 1;
    }
    char buf[64] = {0};
    ssize_t r = read(pf[0], buf, sizeof buf);
    if (r == (ssize_t)n && memcmp(buf, data, n) == 0) {
        w("splice-ok\n");
    } else {
        w("splice-fail: verify\n");
    }
    close(pf[0]);
    close(pf[1]);
    close(mfd);
    return 0;
}
