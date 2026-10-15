// Futex wait semantics smoke: the futex2 family (futex_waitv 449,
// futex_wake 454, futex_wait 455, futex_requeue 456) AND the classic
// futex(2) FUTEX_WAIT / FUTEX_WAIT_BITSET / FUTEX_LOCK_PI waits, all issued
// raw (musl has no futex2 wrappers).
//
// Every expectation is Linux's, and the file runs natively on a Linux host
// to prove it (see REGEN_futex2_smoke.sh). The load-bearing ones:
//
//  * a wait with NO timeout blocks until a wake, a signal, or nothing at
//    all — it never returns on its own. The waker here sleeps well past any
//    "bounded park" a kernel might be tempted to use, then futex_wake must
//    report exactly 1 woken waiter and the waiter must return 0;
//  * a timed wait returns -ETIMEDOUT from the wait itself, at (never before)
//    its deadline, on the clock the caller named;
//  * futex_wake with no waiters reports 0;
//  * futex_waitv reports a moved word as -EAGAIN (futex_wait_multiple_setup
//    returns -EWOULDBLOCK) and a wake on entry N as index N;
//  * futex_requeue returns woken + requeued (futex_requeue's task_count);
//  * a caught signal during an untimed wait restarts it under SA_RESTART
//    (-ERESTARTSYS) and is -EINTR otherwise; the futex2 waits return
//    -ERESTARTSYS even when timed, while a timed classic FUTEX_WAIT returns
//    -ERESTART_RESTARTBLOCK (-EINTR to any handler, SA_RESTART or not);
//  * FUTEX_LOCK_PI is never interrupted (-ERESTARTNOINTR).
//
// Success token "futex2-ok". A hang is reported by SIGALRM with the stage.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

// <linux/futex.h> values (musl ships no kernel headers).
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_BITSET_MATCH_ANY 0xffffffffu

#define FUTEX2_SIZE_U32 0x02
#define FUTEX2_PRIVATE 0x80
#define F2 (FUTEX2_SIZE_U32 | FUTEX2_PRIVATE)
/* futex_validate_input: "every bit" for a 32-bit futex is 0xffffffff. */
#define FUTEX2_MASK_ANY 0xffffffffUL

/* Longer than any bounded-park cap a kernel could hide behind (NARF's old
   FUTEX2_PARK_CAP_NS was 50 ms): an untimed waiter must still be parked. */
#define LONG_PARK_MS 150

struct futex_waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t __reserved;
};

static const char *volatile stage = "start";

static void w(const char *m) { write(1, m, strlen(m)); }

static int fail(const char *what) {
    char buf[256];
    int n = snprintf(buf, sizeof buf, "futex2-fail: %s (errno=%d)\n", what, errno);
    write(1, buf, n);
    exit(1);
}

static void on_alarm(int sig) {
    (void)sig;
    w("futex2-fail: hang in ");
    w(stage);
    w("\n");
    _exit(1);
}

static int64_t now_ns(clockid_t c) {
    struct timespec ts;
    clock_gettime(c, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static struct timespec abs_in(clockid_t c, int64_t ms) {
    int64_t t = now_ns(c) + ms * 1000000LL;
    struct timespec ts = {.tv_sec = t / 1000000000LL, .tv_nsec = t % 1000000000LL};
    return ts;
}

static int64_t ts_ns(const struct timespec *ts) {
    return (int64_t)ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

static void sleep_ms(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static long f2_wait(uint32_t *f, uint32_t val, const struct timespec *to, clockid_t clk) {
    return syscall(SYS_futex_wait, f, (unsigned long)val, FUTEX2_MASK_ANY, (long)F2, to, (long)clk);
}

static long f2_wake(uint32_t *f, int n) {
    return syscall(SYS_futex_wake, f, FUTEX2_MASK_ANY, (long)n, (long)F2);
}

static long fx(uint32_t *f, int op, uint32_t val, const struct timespec *to, uint32_t val3) {
    return syscall(SYS_futex, f, op | FUTEX_PRIVATE_FLAG, val, to, NULL, val3);
}

// ── the waiter thread ────────────────────────────────────────────────

enum kind {
    K_F2_UNTIMED,     /* futex_wait(2), no timeout */
    K_F2_TIMED,       /* futex_wait(2), absolute CLOCK_MONOTONIC deadline */
    K_WAITV_PAIR,     /* futex_waitv on {a, b}, no timeout */
    K_FX_UNTIMED,     /* futex(FUTEX_WAIT), no timeout */
    K_FX_TIMED,       /* futex(FUTEX_WAIT), relative timeout */
    K_FX_LOCK_PI,     /* futex(FUTEX_LOCK_PI), no timeout */
};

struct waiter {
    pthread_t th;
    enum kind kind;
    uint32_t *a, *b;
    uint32_t val;
    int timeout_ms;
    volatile int done;
    long ret;
    int err;
    int64_t elapsed_ns;
};

static void *waiter_main(void *arg) {
    struct waiter *wt = arg;
    struct timespec to;
    int64_t t0 = now_ns(CLOCK_MONOTONIC);
    long r = -1;
    switch (wt->kind) {
    case K_F2_UNTIMED:
        r = f2_wait(wt->a, wt->val, NULL, CLOCK_MONOTONIC);
        break;
    case K_F2_TIMED:
        to = abs_in(CLOCK_MONOTONIC, wt->timeout_ms);
        r = f2_wait(wt->a, wt->val, &to, CLOCK_MONOTONIC);
        break;
    case K_WAITV_PAIR: {
        struct futex_waitv v[2] = {
            {.val = wt->val, .uaddr = (uintptr_t)wt->a, .flags = F2},
            {.val = wt->val, .uaddr = (uintptr_t)wt->b, .flags = F2},
        };
        r = syscall(SYS_futex_waitv, v, 2UL, 0UL, NULL, 0L);
        break;
    }
    case K_FX_UNTIMED:
        r = fx(wt->a, FUTEX_WAIT, wt->val, NULL, 0);
        break;
    case K_FX_TIMED:
        to.tv_sec = wt->timeout_ms / 1000;
        to.tv_nsec = (long)(wt->timeout_ms % 1000) * 1000000L;
        r = fx(wt->a, FUTEX_WAIT, wt->val, &to, 0);
        break;
    case K_FX_LOCK_PI:
        r = fx(wt->a, FUTEX_LOCK_PI, 0, NULL, 0);
        break;
    }
    wt->err = errno;
    wt->ret = r;
    wt->elapsed_ns = now_ns(CLOCK_MONOTONIC) - t0;
    __atomic_store_n(&wt->done, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void start(struct waiter *wt) {
    wt->done = 0;
    if (pthread_create(&wt->th, NULL, waiter_main, wt) != 0)
        fail("pthread_create");
}

static void join(struct waiter *wt) { pthread_join(wt->th, NULL); }

static int is_done(struct waiter *wt) { return __atomic_load_n(&wt->done, __ATOMIC_SEQ_CST); }

// ── signal plumbing ──────────────────────────────────────────────────

static volatile int handled;
static void on_usr1(int sig) {
    (void)sig;
    __atomic_add_fetch(&handled, 1, __ATOMIC_SEQ_CST);
}

static void install_usr1(int restart) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0)
        fail("sigaction");
}

// Interrupt `wt` (parked for ~50 ms) with SIGUSR1 and wait for the handler.
static void interrupt(struct waiter *wt) {
    sleep_ms(50);
    int before = __atomic_load_n(&handled, __ATOMIC_SEQ_CST);
    if (pthread_kill(wt->th, SIGUSR1) != 0)
        fail("pthread_kill");
    while (__atomic_load_n(&handled, __ATOMIC_SEQ_CST) == before)
        sleep_ms(1);
}

// An untimed waiter must still be parked LONG_PARK_MS later, and exactly one
// futex_wake must then release it with 0.
static void expect_parked_then_woken(struct waiter *wt, const char *what, int classic) {
    sleep_ms(LONG_PARK_MS);
    if (is_done(wt))
        fail(what);
    long r = classic ? fx(wt->a, FUTEX_WAKE, 1, NULL, 0) : f2_wake(wt->a, 1);
    if (r != 1)
        fail(what);
    join(wt);
    if (wt->ret != 0)
        fail(what);
}

static void expect_eintr(struct waiter *wt, const char *what) {
    join(wt);
    if (wt->ret != -1 || wt->err != EINTR)
        fail(what);
}

static void expect_timedout(struct waiter *wt, const char *what, int at_least_ms) {
    join(wt);
    if (wt->ret != -1 || wt->err != ETIMEDOUT)
        fail(what);
    if (wt->elapsed_ns < (int64_t)at_least_ms * 1000000LL)
        fail(what);
}

// ── futex2 ───────────────────────────────────────────────────────────

static void futex2_tests(void) {
    uint32_t f = 0xAAAA, g = 0x1234;
    long r;
    struct waiter wt;
    memset(&wt, 0, sizeof wt);

    stage = "f2 eagain";
    r = f2_wait(&f, 0xBBBB, NULL, CLOCK_MONOTONIC);
    if (r != -1 || errno != EAGAIN)
        fail("futex_wait: moved word is not EAGAIN");

    // A deadline already in the past still loses to a moved word:
    // __futex_wait runs futex_wait_setup before it ever looks at the timer.
    stage = "f2 past deadline";
    struct timespec past = {0, 1};
    r = f2_wait(&f, 0xBBBB, &past, CLOCK_MONOTONIC);
    if (r != -1 || errno != EAGAIN)
        fail("futex_wait: moved word with expired deadline is not EAGAIN");
    r = f2_wait(&f, 0xAAAA, &past, CLOCK_MONOTONIC);
    if (r != -1 || errno != ETIMEDOUT)
        fail("futex_wait: expired deadline is not ETIMEDOUT");

    stage = "f2 timed monotonic";
    struct timespec dl = abs_in(CLOCK_MONOTONIC, 100);
    r = f2_wait(&f, 0xAAAA, &dl, CLOCK_MONOTONIC);
    if (r != -1 || errno != ETIMEDOUT)
        fail("futex_wait: timed wait is not ETIMEDOUT");
    if (now_ns(CLOCK_MONOTONIC) < ts_ns(&dl))
        fail("futex_wait: CLOCK_MONOTONIC deadline returned early");

    stage = "f2 timed realtime";
    dl = abs_in(CLOCK_REALTIME, 100);
    r = f2_wait(&f, 0xAAAA, &dl, CLOCK_REALTIME);
    if (r != -1 || errno != ETIMEDOUT)
        fail("futex_wait: CLOCK_REALTIME wait is not ETIMEDOUT");
    if (now_ns(CLOCK_REALTIME) < ts_ns(&dl))
        fail("futex_wait: CLOCK_REALTIME deadline returned early");

    stage = "f2 wake nobody";
    r = f2_wake(&f, 1);
    if (r != 0)
        fail("futex_wake: no waiters must report 0");

    stage = "f2 untimed park";
    wt = (struct waiter){.kind = K_F2_UNTIMED, .a = &f, .val = 0xAAAA};
    start(&wt);
    expect_parked_then_woken(&wt, "futex_wait: untimed waiter not parked / not woken", 0);

    // ── futex_waitv ──
    stage = "waitv eagain";
    struct futex_waitv wv = {.val = 0xBBBB, .uaddr = (uintptr_t)&f, .flags = F2};
    r = syscall(SYS_futex_waitv, &wv, 1UL, 0UL, NULL, 0L);
    if (r != -1 || errno != EAGAIN)
        fail("futex_waitv: moved word is not EAGAIN");

    stage = "waitv timed";
    wv.val = 0xAAAA;
    dl = abs_in(CLOCK_MONOTONIC, 100);
    r = syscall(SYS_futex_waitv, &wv, 1UL, 0UL, &dl, (long)CLOCK_MONOTONIC);
    if (r != -1 || errno != ETIMEDOUT)
        fail("futex_waitv: timed wait is not ETIMEDOUT");
    if (now_ns(CLOCK_MONOTONIC) < ts_ns(&dl))
        fail("futex_waitv: deadline returned early");

    // A wake on the SECOND word must release the waiter with index 1.
    stage = "waitv second word";
    uint32_t a = 7, b = 7;
    wt = (struct waiter){.kind = K_WAITV_PAIR, .a = &a, .b = &b, .val = 7};
    start(&wt);
    sleep_ms(LONG_PARK_MS);
    if (is_done(&wt))
        fail("futex_waitv: untimed waiter not parked");
    if (f2_wake(&b, 1) != 1)
        fail("futex_waitv: wake on entry 1 did not find the waiter");
    join(&wt);
    if (wt.ret != 1)
        fail("futex_waitv: wake on entry 1 must return index 1");

    // ── futex_requeue ──
    // cmpval = futexes[0].w.val, and a moved *uaddr1 is -EAGAIN.
    stage = "requeue";
    struct futex_waitv stale[2] = {
        {.val = 0, .uaddr = (uintptr_t)&f, .flags = F2},
        {.val = 0, .uaddr = (uintptr_t)&g, .flags = F2},
    };
    r = syscall(SYS_futex_requeue, stale, 0L, 1L, 0L);
    if (r != -1 || errno != EAGAIN)
        fail("futex_requeue: stale compare is not EAGAIN");
    struct futex_waitv pair[2] = {
        {.val = 0xAAAA, .uaddr = (uintptr_t)&f, .flags = F2},
        {.val = 0, .uaddr = (uintptr_t)&g, .flags = F2},
    };
    r = syscall(SYS_futex_requeue, pair, 0L, 1L, 0L);
    if (r != 0)
        fail("futex_requeue: no waiters must report 0");
    // A parked waiter on f is moved (not woken) onto g; a wake on g then
    // releases it.
    wt = (struct waiter){.kind = K_F2_UNTIMED, .a = &f, .val = 0xAAAA};
    start(&wt);
    sleep_ms(50);
    r = syscall(SYS_futex_requeue, pair, 0L, 0L /*nr_wake*/, 1L /*nr_requeue*/);
    if (r != 1)
        fail("futex_requeue: one requeued waiter must report 1");
    sleep_ms(50);
    if (is_done(&wt))
        fail("futex_requeue: requeued waiter returned without a wake");
    if (f2_wake(&f, 1) != 0)
        fail("futex_requeue: waiter still queued on the source word");
    if (f2_wake(&g, 1) != 1)
        fail("futex_requeue: requeued waiter not queued on the target word");
    join(&wt);
    if (wt.ret != 0)
        fail("futex_requeue: requeued waiter must return 0");

    // ── signals ──
    // SA_RESTART: -ERESTARTSYS restarts the untimed wait; it stays parked
    // until a real wake.
    stage = "f2 untimed SA_RESTART";
    install_usr1(1);
    wt = (struct waiter){.kind = K_F2_UNTIMED, .a = &f, .val = 0xAAAA};
    start(&wt);
    interrupt(&wt);
    expect_parked_then_woken(&wt, "futex_wait: SA_RESTART did not restart the wait", 0);

    // futex2's wait returns -ERESTARTSYS even with a timeout, so SA_RESTART
    // restarts a TIMED futex_wait too and it still times out at its deadline.
    stage = "f2 timed SA_RESTART";
    wt = (struct waiter){.kind = K_F2_TIMED, .a = &f, .val = 0xAAAA, .timeout_ms = 300};
    start(&wt);
    interrupt(&wt);
    expect_timedout(&wt, "futex_wait: SA_RESTART timed wait is not ETIMEDOUT", 300);

    stage = "f2 untimed no SA_RESTART";
    install_usr1(0);
    wt = (struct waiter){.kind = K_F2_UNTIMED, .a = &f, .val = 0xAAAA};
    start(&wt);
    interrupt(&wt);
    expect_eintr(&wt, "futex_wait: signal without SA_RESTART is not EINTR");

    stage = "waitv no SA_RESTART";
    wt = (struct waiter){.kind = K_WAITV_PAIR, .a = &a, .b = &b, .val = 7};
    start(&wt);
    interrupt(&wt);
    expect_eintr(&wt, "futex_waitv: signal without SA_RESTART is not EINTR");
}

// ── classic futex(2) ─────────────────────────────────────────────────

static void classic_tests(void) {
    uint32_t f = 5;
    long r;
    struct waiter wt;
    memset(&wt, 0, sizeof wt);

    stage = "fx eagain";
    r = fx(&f, FUTEX_WAIT, 6, NULL, 0);
    if (r != -1 || errno != EAGAIN)
        fail("FUTEX_WAIT: moved word is not EAGAIN");

    stage = "fx relative timeout";
    struct timespec rel = {0, 100 * 1000000L};
    int64_t t0 = now_ns(CLOCK_MONOTONIC);
    r = fx(&f, FUTEX_WAIT, 5, &rel, 0);
    if (r != -1 || errno != ETIMEDOUT)
        fail("FUTEX_WAIT: timed wait is not ETIMEDOUT");
    if (now_ns(CLOCK_MONOTONIC) - t0 < 100 * 1000000LL)
        fail("FUTEX_WAIT: relative timeout returned early");

    stage = "fx bitset monotonic";
    struct timespec dl = abs_in(CLOCK_MONOTONIC, 100);
    r = fx(&f, FUTEX_WAIT_BITSET, 5, &dl, FUTEX_BITSET_MATCH_ANY);
    if (r != -1 || errno != ETIMEDOUT)
        fail("FUTEX_WAIT_BITSET: timed wait is not ETIMEDOUT");
    if (now_ns(CLOCK_MONOTONIC) < ts_ns(&dl))
        fail("FUTEX_WAIT_BITSET: CLOCK_MONOTONIC deadline returned early");

    stage = "fx bitset realtime";
    dl = abs_in(CLOCK_REALTIME, 100);
    r = fx(&f, FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME, 5, &dl, FUTEX_BITSET_MATCH_ANY);
    if (r != -1 || errno != ETIMEDOUT)
        fail("FUTEX_WAIT_BITSET|CLOCK_REALTIME: timed wait is not ETIMEDOUT");
    if (now_ns(CLOCK_REALTIME) < ts_ns(&dl))
        fail("FUTEX_WAIT_BITSET|CLOCK_REALTIME: deadline returned early");

    stage = "fx wake nobody";
    if (fx(&f, FUTEX_WAKE, 1, NULL, 0) != 0)
        fail("FUTEX_WAKE: no waiters must report 0");

    stage = "fx untimed park";
    wt = (struct waiter){.kind = K_FX_UNTIMED, .a = &f, .val = 5};
    start(&wt);
    expect_parked_then_woken(&wt, "FUTEX_WAIT: untimed waiter not parked / not woken", 1);

    // Untimed FUTEX_WAIT: -ERESTARTSYS.
    stage = "fx untimed SA_RESTART";
    install_usr1(1);
    wt = (struct waiter){.kind = K_FX_UNTIMED, .a = &f, .val = 5};
    start(&wt);
    interrupt(&wt);
    expect_parked_then_woken(&wt, "FUTEX_WAIT: SA_RESTART did not restart the wait", 1);

    // Timed FUTEX_WAIT: -ERESTART_RESTARTBLOCK, which handle_signal turns
    // into -EINTR for every handler, SA_RESTART included.
    stage = "fx timed SA_RESTART";
    wt = (struct waiter){.kind = K_FX_TIMED, .a = &f, .val = 5, .timeout_ms = 2000};
    start(&wt);
    interrupt(&wt);
    expect_eintr(&wt, "FUTEX_WAIT: timed wait + SA_RESTART handler is not EINTR");

    stage = "fx untimed no SA_RESTART";
    install_usr1(0);
    wt = (struct waiter){.kind = K_FX_UNTIMED, .a = &f, .val = 5};
    start(&wt);
    interrupt(&wt);
    expect_eintr(&wt, "FUTEX_WAIT: signal without SA_RESTART is not EINTR");

    // FUTEX_LOCK_PI: -ERESTARTNOINTR — a handler (no SA_RESTART) runs and the
    // lock attempt resumes; it returns 0 only once it owns the lock.
    stage = "fx lock_pi signal";
    uint32_t pi = (uint32_t)syscall(SYS_gettid);
    wt = (struct waiter){.kind = K_FX_LOCK_PI, .a = &pi};
    start(&wt);
    interrupt(&wt);
    sleep_ms(50);
    if (is_done(&wt))
        fail("FUTEX_LOCK_PI: a signal interrupted the lock");
    if (fx(&pi, FUTEX_UNLOCK_PI, 0, NULL, 0) != 0)
        fail("FUTEX_UNLOCK_PI");
    join(&wt);
    if (wt.ret != 0)
        fail("FUTEX_LOCK_PI: waiter did not acquire the lock");
}

// A timed FUTEX_WAIT that a job-control stop interrupts restarts through
// restart_block with the REMAINING time (futex_wait_restart reuses the
// absolute expiry): the stop must not extend the wait. Run in a child so the
// SIGSTOP stops only it.
static void restart_block_test(void) {
    stage = "fx restart_block";
    pid_t child = fork();
    if (child < 0)
        fail("fork");
    if (child == 0) {
        uint32_t f = 1;
        struct timespec rel = {0, 600 * 1000000L};
        int64_t t0 = now_ns(CLOCK_MONOTONIC);
        long r = fx(&f, FUTEX_WAIT, 1, &rel, 0);
        int64_t el = now_ns(CLOCK_MONOTONIC) - t0;
        if (r != -1 || errno != ETIMEDOUT)
            _exit(2);
        if (el < 600 * 1000000LL)
            _exit(3);
        /* A restart that re-read the RELATIVE timeout would run >= 900 ms. */
        if (el >= 850 * 1000000LL)
            _exit(4);
        _exit(0);
    }
    sleep_ms(150);
    kill(child, SIGSTOP);
    sleep_ms(150);
    kill(child, SIGCONT);
    int st = 0;
    if (waitpid(child, &st, 0) != child)
        fail("waitpid");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        char buf[96];
        int n = snprintf(buf, sizeof buf, "FUTEX_WAIT: stopped timed wait (child status %d)",
                         WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        buf[n] = 0;
        fail(buf);
    }
}

int main(void) {
    signal(SIGALRM, on_alarm);
    alarm(60);
    futex2_tests();
    classic_tests();
    restart_block_test();
    w("futex2-ok\n");
    return 0;
}
