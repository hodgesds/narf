// Protection-keys smoke. Allocate a key, apply it to an anonymous page
// via pkey_mprotect, confirm an unallocated key is rejected with EINVAL,
// then free the key and confirm a double-free fails. Keys are tracked but
// not hardware-enforced. Success token "pkey-ok".
//
// Build: see REGEN_pkey_smoke.sh (musl-gcc, static-PIE).
// musl gates the pkey_* wrappers behind a version this toolchain lacks,
// so issue them raw via syscall(2).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    long k = syscall(SYS_pkey_alloc, 0UL, 0UL);
    if (k < 0) { w("pkey-fail: alloc\n"); return 1; }

    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { w("pkey-fail: mmap\n"); return 1; }

    if (syscall(SYS_pkey_mprotect, p, (size_t)4096, (long)PROT_READ, k) != 0) {
        w("pkey-fail: mprotect\n"); return 1;
    }

    // An unallocated key must be rejected with EINVAL.
    if (syscall(SYS_pkey_mprotect, p, (size_t)4096, (long)PROT_READ, 9L) != -1 ||
        errno != EINVAL) {
        w("pkey-fail: badkey\n"); return 1;
    }

    if (syscall(SYS_pkey_free, k) != 0) { w("pkey-fail: free\n"); return 1; }
    if (syscall(SYS_pkey_free, k) == 0) { w("pkey-fail: free-twice\n"); return 1; }

    w("pkey-ok\n");
    return 0;
}
