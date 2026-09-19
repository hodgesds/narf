// FUTEX_WAKE_OP atomicity stressor.
//
// `futex(FUTEX_WAKE_OP)` performs a read-modify-write on the word at
// `uaddr2` — Linux does it with a single locked instruction on the user
// address (`arch/x86/include/asm/futex.h`: `xchgl`, `LOCK_PREFIX xaddl`,
// or a `cmpxchg` loop). A kernel that instead does a plain read, a
// computation, and a plain write can have another CPU's update land in
// the gap, and that update is then overwritten and lost.
//
// A lost update on a futex word is not a visible failure at the time. It
// surfaces later as a condvar that never wakes or a mutex that stays
// locked, which is why this asserts an EXACT arithmetic invariant rather
// than looking for a hang: every increment is counted, so any loss is a
// number, not a timeout.
//
//   Phase 1 — N threads each issue ITERS FUTEX_OP_ADD(1) on one shared
//             word. An atomic kernel leaves it at exactly N*ITERS.
//
//   Phase 2 — the sharper case, which needs no kernel-side concurrency
//             at all: half the threads drive FUTEX_OP_ADD(1) through the
//             kernel while the other half do a userspace `__atomic`
//             increment on the SAME word. A non-atomic kernel RMW loses
//             the userspace increments that land mid-gap. This is the
//             real pthread pattern — a condvar broadcast touching the
//             mutex word while another thread is unlocking it.
//
// Both phases need user tasks running on more than one CPU, so this only
// means anything in a build where user-task SMP is live (`boot-init`,
// x2APIC). Under `kernel-test` the scheduler keeps every user task on the
// BSP and the race cannot occur — a pass there proves nothing.
//
// Success token "futex-wakeop-ok".
//
// Build: see REGEN_futex_wakeop_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdint.h>

static void w(const char *m) { write(1, m, strlen(m)); }

// Render an unsigned value so a failure reports the DEFICIT, not just
// "wrong" — the size of the loss says how wide the race window is.
static void wnum(unsigned long v) {
    char b[24];
    int i = sizeof(b);
    b[--i] = '\n';
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = (char)('0' + (v % 10)); v /= 10; }
    write(1, &b[i], sizeof(b) - (size_t)i);
}

#define FUTEX_WAKE_OP 5
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_OP_ADD 1
#define FUTEX_OP_CMP_NE 1

#define NTHREAD 8
#define ITERS 20000

// The word the kernel read-modify-writes. Cache-line isolated so the
// contention is on this word alone and not shared with the bookkeeping
// below, which would blur where a loss came from.
static volatile uint32_t target __attribute__((aligned(64)));
// A second word, only ever used as the `uaddr` the wake half addresses.
// Nothing waits on it; WAKE_OP still requires a valid address there.
static volatile uint32_t wake_word __attribute__((aligned(64)));

// encoded_op: [31:28] op, [27:24] cmp, [23:12] oparg, [11:0] cmparg.
// FUTEX_OP_ADD(1), compared CMP_NE against 0 — the comparison only
// decides whether the second wake fires, and nr_wake2 is 0, so it cannot
// affect the arithmetic under test.
#define ENCODED_ADD1 \
    (((uint32_t)FUTEX_OP_ADD << 28) | ((uint32_t)FUTEX_OP_CMP_NE << 24) | ((uint32_t)1 << 12))

static long wake_op_add1(void) {
    return syscall(SYS_futex, (uint32_t *)&wake_word,
                   FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG,
                   0,                       // nr_wake — no waiters to wake
                   (void *)0,               // nr_wake2, passed in the timeout slot
                   (uint32_t *)&target,     // uaddr2 — the word we RMW
                   ENCODED_ADD1);
}

static void *kernel_bump(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        if (wake_op_add1() < 0) return (void *)1;
    }
    return NULL;
}

static void *user_bump(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++)
        __atomic_fetch_add((uint32_t *)&target, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

// Run `n` threads, half of them `a` and half `b` when `b` is non-NULL.
// Returns non-zero if any thread reported a syscall failure.
static int run(void *(*a)(void *), void *(*b)(void *), int n) {
    pthread_t t[NTHREAD];
    for (int i = 0; i < n; i++) {
        void *(*fn)(void *) = (b && (i & 1)) ? b : a;
        if (pthread_create(&t[i], NULL, fn, NULL) != 0) return -1;
    }
    int bad = 0;
    for (int i = 0; i < n; i++) {
        void *r = NULL;
        pthread_join(t[i], &r);
        if (r) bad = 1;
    }
    return bad;
}

int main(void) {
    // Phase 1: every increment through the kernel.
    target = 0;
    int rc = run(kernel_bump, NULL, NTHREAD);
    if (rc < 0) { w("futex-wakeop-fail: create\n"); return 1; }
    if (rc > 0) { w("futex-wakeop-fail: syscall\n"); return 1; }
    if (target != (uint32_t)NTHREAD * ITERS) {
        w("futex-wakeop-fail: kernel-only lost updates, deficit=");
        wnum((unsigned long)((uint32_t)NTHREAD * ITERS - target));
        return 1;
    }

    // Phase 2: kernel RMW racing userspace's own atomic on the same word.
    target = 0;
    rc = run(kernel_bump, user_bump, NTHREAD);
    if (rc < 0) { w("futex-wakeop-fail: create2\n"); return 1; }
    if (rc > 0) { w("futex-wakeop-fail: syscall2\n"); return 1; }
    if (target != (uint32_t)NTHREAD * ITERS) {
        w("futex-wakeop-fail: kernel-vs-user lost updates, deficit=");
        wnum((unsigned long)((uint32_t)NTHREAD * ITERS - target));
        return 1;
    }

    w("futex-wakeop-ok\n");
    return 0;
}
