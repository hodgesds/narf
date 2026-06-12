// msync(2) + mincore(2) smoke. mmap two anonymous pages, touch the
// first, msync the mapping, then mincore it and verify the touched
// page reads back as resident. Success token "mcore-ok".
//
// Build: see REGEN_mcore_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    size_t len = 8192; // 2 pages
    char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        w("mcore-fail: mmap\n");
        return 1;
    }
    p[0] = 'x'; // fault in page 0

    if (msync(p, len, MS_SYNC) != 0) {
        w("mcore-fail: msync\n");
        return 1;
    }

    unsigned char vec[2] = {0, 0};
    if (mincore(p, len, vec) != 0) {
        w("mcore-fail: mincore\n");
        return 1;
    }
    if (!(vec[0] & 1)) {
        w("mcore-fail: resident\n");
        return 1;
    }
    w("mcore-ok\n");
    munmap(p, len);
    return 0;
}
