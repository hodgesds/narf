// mremap(2) smoke. mmap an anonymous page, fill it, grow it with
// mremap(MREMAP_MAYMOVE), and verify the original contents survived
// and the grown tail is writable. Success token "mremap-ok".
//
// Build: see REGEN_mremap_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    size_t old = 4096, neu = 8192;
    char *p = mmap(NULL, old, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        w("mremap-fail: mmap\n");
        return 1;
    }
    memset(p, 'A', old);

    char *q = mremap(p, old, neu, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) {
        w("mremap-fail: mremap\n");
        return 1;
    }
    // Original contents must survive the resize.
    for (size_t i = 0; i < old; i++) {
        if (q[i] != 'A') {
            w("mremap-fail: content\n");
            return 1;
        }
    }
    // Grown tail must be usable.
    memset(q + old, 'B', neu - old);
    for (size_t i = old; i < neu; i++) {
        if (q[i] != 'B') {
            w("mremap-fail: grow\n");
            return 1;
        }
    }
    w("mremap-ok\n");
    munmap(q, neu);
    return 0;
}
