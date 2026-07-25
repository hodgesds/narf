// Memory family smoke: mlockall/munlockall, memfd_secret, move_pages,
// set_mempolicy_home_node, migrate_pages, process_madvise. The NUMA +
// secret-memory syscalls have no musl wrappers, so they're issued raw.
// Success token "mem2-ok".
//
// (On a host where secretmem is disabled, memfd_secret returns ENOSYS —
// expected; the real gate is the NARF musl-demo run.)
//
// Build: see REGEN_mem2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>

// Older musl-tools (CI) predate these syscall numbers in <sys/syscall.h>.
// Pin the x86_64 wire numbers so the smoke builds regardless of header age;
// NARF dispatches on the number, not the libc wrapper.
#ifndef SYS_migrate_pages
#define SYS_migrate_pages 256
#endif
#ifndef SYS_move_pages
#define SYS_move_pages 279
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif
#ifndef SYS_memfd_secret
#define SYS_memfd_secret 447
#endif
#ifndef SYS_set_mempolicy_home_node
#define SYS_set_mempolicy_home_node 450
#endif

static void w(const char *m) { write(1, m, strlen(m)); }

#define MADV_DONTNEED 4

int main(void) {
    // ── mlockall / munlockall ──
    if (mlockall(MCL_CURRENT) != 0) { w("mem2-fail: mlockall\n"); return 1; }
    if (munlockall() != 0) { w("mem2-fail: munlockall\n"); return 1; }

    // ── memfd_secret: anonymous fd-backed memory ──
    long sfd = syscall(SYS_memfd_secret, 0UL);
    if (sfd < 0) { w("mem2-fail: memfd_secret\n"); return 1; }
    if (ftruncate((int)sfd, 4096) != 0) { w("mem2-fail: ftruncate\n"); return 1; }
    char *sm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, (int)sfd, 0);
    if (sm == MAP_FAILED) { w("mem2-fail: secret-mmap\n"); return 1; }
    memcpy(sm, "secret-data", 11);
    if (memcmp(sm, "secret-data", 11) != 0) { w("mem2-fail: secret-rw\n"); return 1; }
    munmap(sm, 4096);
    close((int)sfd);

    // A working anonymous page for the NUMA / madvise calls.
    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { w("mem2-fail: mmap\n"); return 1; }
    p[0] = 1; // fault it in

    // ── move_pages: status query reports node 0 ──
    void *pages[1] = { p };
    int status[1] = { -1 };
    if (syscall(SYS_move_pages, 0L, 1L, pages, (void *)0, status, 0L) != 0) {
        w("mem2-fail: move_pages\n"); return 1;
    }
    if (status[0] != 0) { w("mem2-fail: move_pages-node\n"); return 1; }

    // ── set_mempolicy_home_node / migrate_pages: accepted ──
    if (syscall(SYS_set_mempolicy_home_node, p, (size_t)4096, 0L, 0L) != 0) {
        w("mem2-fail: home_node\n"); return 1;
    }
    unsigned long old_nodes = 1UL;
    unsigned long new_nodes = 1UL;
    if (syscall(SYS_migrate_pages, 0L, 64L, &old_nodes, &new_nodes) != 0) {
        w("mem2-fail: migrate_pages\n"); return 1;
    }

    // ── process_madvise on our own AS (via a self pidfd) ──
    long pidfd = syscall(SYS_pidfd_open, (long)getpid(), 0L);
    if (pidfd < 0) { w("mem2-fail: pidfd_open\n"); return 1; }
    struct iovec iov = { p, 4096 };
    long n = syscall(SYS_process_madvise, pidfd, &iov, 1L, (long)MADV_DONTNEED, 0L);
    if (n != 4096) { w("mem2-fail: process_madvise\n"); return 1; }
    close((int)pidfd);

    w("mem2-ok\n");
    return 0;
}
