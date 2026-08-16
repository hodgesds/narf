// mremap(2) smoke. Exercise real shrink, collision-driven MAYMOVE growth,
// FIXED replacement, content preservation, lazy grown-tail backing, and the
// explicitly unsupported DONTUNMAP contract. Success token "mremap-ok".
//
// Build: see REGEN_mremap_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    const size_t pg = 4096;
    size_t old = 4 * pg;
    char *p = mmap(NULL, old, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        w("mremap-fail: mmap\n");
        return 1;
    }
    for (size_t page = 0; page < 4; page++)
        memset(p + page * pg, 'A' + page, pg);

    // Shrink must really remove the tail, not merely report success.
    char *shrunk = mremap(p, old, 2 * pg, 0);
    if (shrunk != p) {
        w("mremap-fail: shrink\n");
        return 1;
    }

    // Occupy the in-place growth tail so MAYMOVE is required.
    char *blocker = mmap(p + 2 * pg, 2 * pg, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (blocker != p + 2 * pg) {
        w("mremap-fail: blocker\n");
        return 1;
    }
    memset(blocker, 'X', 2 * pg);

    char *q = mremap(p, 2 * pg, 4 * pg, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) {
        w("mremap-fail: maymove\n");
        return 1;
    }
    if (q == p) {
        w("mremap-fail: collision did not move\n");
        return 1;
    }
    // Original contents must survive the resize.
    for (size_t page = 0; page < 2; page++) {
        for (size_t i = 0; i < pg; i++) {
            if (q[page * pg + i] != 'A' + (char)page) {
                w("mremap-fail: content\n");
                return 1;
            }
        }
    }
    // Grown tail must demand-page and remain writable.
    memset(q + 2 * pg, 'G', 2 * pg);
    for (size_t i = 2 * pg; i < 4 * pg; i++) {
        if (q[i] != 'G') {
            w("mremap-fail: grow\n");
            return 1;
        }
    }

    // DONTUNMAP cannot be approximated as an ordinary writable alias. NARF
    // rejects it with EINVAL until userfaultfd-style old-range faults exist.
    errno = 0;
    if (mremap(q, 4 * pg, 4 * pg, MREMAP_MAYMOVE | MREMAP_DONTUNMAP) != MAP_FAILED
        || errno != EINVAL) {
        w("mremap-fail: dontunmap\n");
        return 1;
    }

    // MREMAP_FIXED replaces an existing disjoint target and may resize while
    // moving. The first three pages must preserve their bytes.
    char *target = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        w("mremap-fail: fixed target mmap\n");
        return 1;
    }
    memset(target, 'T', 3 * pg);
    char *fixed = mremap(q, 4 * pg, 3 * pg,
                         MREMAP_MAYMOVE | MREMAP_FIXED, target);
    if (fixed != target) {
        w("mremap-fail: fixed\n");
        return 1;
    }
    for (size_t page = 0; page < 3; page++) {
        const char expected = page < 2 ? 'A' + (char)page : 'G';
        for (size_t i = 0; i < pg; i++) {
            if (fixed[page * pg + i] != expected) {
                w("mremap-fail: fixed content\n");
                return 1;
            }
        }
    }

    if (munmap(blocker, 2 * pg) != 0 || munmap(fixed, 3 * pg) != 0) {
        w("mremap-fail: munmap\n");
        return 1;
    }
    w("mremap-ok\n");
    return 0;
}
