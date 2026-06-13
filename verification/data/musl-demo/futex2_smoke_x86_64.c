// Futex2 smoke: the futex_waitv / futex_wake / futex_wait / futex_requeue
// family (x86_64 449/454/455/456). These have no musl wrappers, so they're
// issued raw. NARF implements them on the same cooperative wait/wake core
// the classic futex(2) uses: value-checked waits that park the caller via a
// bounded yield, and a per-uaddr counter that wakes parked waiters.
//
// Single-threaded coverage exercises every dispatch path and both wait
// outcomes — the immediate EAGAIN fast path (value already moved) and the
// real park-and-resume path (value matches ⇒ the task yields to the
// executor and comes back with 0). Success token "futex2-ok".
//
// Build: see REGEN_futex2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif
#ifndef SYS_futex_wake
#define SYS_futex_wake 454
#endif
#ifndef SYS_futex_wait
#define SYS_futex_wait 455
#endif
#ifndef SYS_futex_requeue
#define SYS_futex_requeue 456
#endif

// FUTEX2 flag selecting the 32-bit access width (the only width NARF parks
// on); the kernel-side handlers don't enforce it, but real callers pass it.
#define FUTEX2_SIZE_U32 0x02

struct futex_waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t __reserved;
};

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    uint32_t f = 0xAAAA;

    // ── futex_wait fast path: value already differs ⇒ EAGAIN, no park ──
    long r = syscall(SYS_futex_wait, &f, 0xBBBBUL, ~0UL,
                     (long)FUTEX2_SIZE_U32, (void *)0, 0L);
    if (r != -1 || errno != EAGAIN) { w("futex2-fail: wait-eagain\n"); return 1; }

    // ── futex_wait real path: value matches ⇒ task parks (bounded yield)
    //    and resumes with 0. Proves the cooperative wait actually runs. ──
    r = syscall(SYS_futex_wait, &f, 0xAAAAUL, ~0UL,
                (long)FUTEX2_SIZE_U32, (void *)0, 0L);
    if (r != 0) { w("futex2-fail: wait-park\n"); return 1; }

    // ── futex_wake: release waiters on the word (bumps the wake counter) ──
    r = syscall(SYS_futex_wake, &f, ~0UL, 1L, (long)FUTEX2_SIZE_U32);
    if (r != 1) { w("futex2-fail: wake\n"); return 1; }

    // ── futex_waitv: a word whose value already moved is reported by index ──
    struct futex_waitv wv = {
        .val = 0xBBBB, .uaddr = (uint64_t)(uintptr_t)&f,
        .flags = FUTEX2_SIZE_U32, .__reserved = 0,
    };
    r = syscall(SYS_futex_waitv, &wv, 1UL, 0UL, (void *)0, 0L);
    if (r != 0) { w("futex2-fail: waitv\n"); return 1; }

    // ── futex_requeue: [src,dst] pair; wakes the source, reports nr_wake ──
    uint32_t g = 0x1234;
    struct futex_waitv pair[2] = {
        { .val = 0, .uaddr = (uint64_t)(uintptr_t)&f, .flags = FUTEX2_SIZE_U32 },
        { .val = 0, .uaddr = (uint64_t)(uintptr_t)&g, .flags = FUTEX2_SIZE_U32 },
    };
    r = syscall(SYS_futex_requeue, pair, 0L, 1L /*nr_wake*/, 0L /*nr_requeue*/);
    if (r != 1) { w("futex2-fail: requeue\n"); return 1; }

    w("futex2-ok\n");
    return 0;
}
