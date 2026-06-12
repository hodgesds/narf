// NUMA memory-policy smoke. musl has no wrappers for the mempolicy
// syscalls (those live in libnuma), so issue them raw. Set a default
// policy, read it back, and apply a range policy via mbind. Success
// token "mpol-ok".
//
// Build: see REGEN_mempolicy_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define MPOL_DEFAULT 0
#define MPOL_PREFERRED 1
#define MPOL_BIND 2

int main(void) {
    unsigned long nodemask = 1UL; // node 0
    if (syscall(SYS_set_mempolicy, MPOL_BIND, &nodemask, 8L) != 0) {
        w("mpol-fail: set\n"); return 1;
    }

    int mode = -1;
    unsigned long got = 0;
    if (syscall(SYS_get_mempolicy, &mode, &got, 8L, 0UL, 0UL) != 0) {
        w("mpol-fail: get\n"); return 1;
    }
    if (mode != MPOL_BIND) { w("mpol-fail: mode\n"); return 1; }

    // mbind a freshly-mapped region.
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { w("mpol-fail: mmap\n"); return 1; }
    if (syscall(SYS_mbind, p, (size_t)4096, MPOL_PREFERRED, &nodemask, 8L, 0UL) != 0) {
        w("mpol-fail: mbind\n"); return 1;
    }

    // An invalid mode must be rejected.
    if (syscall(SYS_set_mempolicy, 99, &nodemask, 8L) != -1) {
        w("mpol-fail: badmode\n"); return 1;
    }

    w("mpol-ok\n");
    return 0;
}
