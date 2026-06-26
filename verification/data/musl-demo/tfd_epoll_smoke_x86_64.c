/* timerfd-in-epoll wake smoke — reproduces weston's repaint-loop driver.
 *
 * libwayland's event loop arms a timerfd and blocks in epoll_wait() with an
 * INFINITE (-1) timeout; the only thing that un-blocks it for a frame is the
 * timerfd becoming readable. weston's whole repaint cadence rides on this:
 * output_repaint_timer_arm() -> wl_event_source_timer_update() -> timerfd_settime(),
 * then the loop's epoll_wait(-1) must return when that timer fires.
 *
 * NARF's other epoll smoke only tests a pipe write with a 5s timeout, so it
 * never exercises the (timerfd, timeout=-1) path. This one does, in stages, so
 * a single boot pins exactly which link breaks:
 *   step A: does the timerfd become readable on a *plain* poll()?      (timer itself)
 *   step B: does it wake epoll_wait() with a *finite* timeout *at the
 *           timer deadline* (not on a coarse fallback)?               (timerfd-in-epoll)
 *   step C: does it wake epoll_wait(-1)?                              (the weston pattern)
 *   step D: ABSTIME timerfd armed off clock_gettime (vDSO/kernel clock match)
 *   step E: does a PURE-timeout epoll_wait (no fd ready) return at its deadline?
 *   step F: ditto for poll(2) — libwayland's client-side blocking primitive.
 *
 * Each armed timer is ~30ms out, so a correct waker lands every step well under
 * the 250ms gate. The pre-fix bug woke step B only on epoll's ~2s park fallback
 * (~2200ms) and hung step C forever; steps E/F pin a later regression where a
 * pure-timeout epoll_wait/poll re-armed its deadline forever and never returned.
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#define PERIOD_MS 30
#define GATE_MS   250

static void w(const char *m) { write(1, m, strlen(m)); }
static void wkv(const char *tag, long v) {
    char b[96]; snprintf(b, sizeof b, "%s=%ld\n", tag, v); w(b);
}
static int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void arm(int tfd) {
    struct itimerspec its = {0};
    its.it_value.tv_nsec = PERIOD_MS * 1000000L;
    timerfd_settime(tfd, 0, &its, NULL);
}

int main(void) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) { w("tfd-epoll-fail: create\n"); return 1; }
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = tfd };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) != 0) {
        w("tfd-epoll-fail: ctl\n"); return 1;
    }

    int64_t worst = 0;

    /* step A: plain poll() — is the timerfd itself becoming readable? */
    arm(tfd);
    struct pollfd pfd = { .fd = tfd, .events = POLLIN };
    int64_t t0 = now_ms();
    int pr = poll(&pfd, 1, 2000);
    int64_t dt = now_ms() - t0;
    wkv("step-A poll_n", pr); wkv("step-A elapsed_ms", (long)dt);
    if (pr != 1 || !(pfd.revents & POLLIN)) { w("tfd-epoll-fail: A\n"); return 1; }
    { uint64_t e = 0; read(tfd, &e, sizeof e); }

    /* step B: epoll with a FINITE timeout — must wake at the ~30ms timer
     * deadline, NOT on epoll's coarse park fallback. */
    arm(tfd);
    struct epoll_event out[1];
    t0 = now_ms();
    int n = epoll_wait(epfd, out, 1, 2000);
    dt = now_ms() - t0;
    wkv("step-B epoll_n", n); wkv("step-B elapsed_ms", (long)dt);
    if (n != 1 || out[0].data.fd != tfd) { w("tfd-epoll-fail: B\n"); return 1; }
    if (dt > worst) worst = dt;
    { uint64_t e = 0; read(tfd, &e, sizeof e); }

    /* step C: THE weston pattern — epoll_wait(-1), woken only by the timer. */
    arm(tfd);
    t0 = now_ms();
    n = epoll_wait(epfd, out, 1, -1);
    dt = now_ms() - t0;
    wkv("step-C epoll_n", n); wkv("step-C elapsed_ms", (long)dt);
    if (n != 1 || out[0].data.fd != tfd) { w("tfd-epoll-fail: C\n"); return 1; }
    if (dt > worst) worst = dt;
    { uint64_t e = 0; read(tfd, &e, sizeof e); }

    /* step D: ABSTIME timer armed from clock_gettime(CLOCK_MONOTONIC), the way
     * libwayland's event loop arms its repaint timer. This crosses the vDSO
     * clock (what clock_gettime reads) and the kernel timerfd clock: if those
     * timebases diverge, the absolute deadline lands in the wrong frame and the
     * wakeup is late by ~0.1·uptime — which is what stalled weston's repaint.
     * (A relative timer can't catch it; the deadline must be ABSOLUTE.) */
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_nsec += PERIOD_MS * 1000000L;
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
        struct itimerspec its = {0};
        its.it_value = ts;
        if (timerfd_settime(tfd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
            w("tfd-epoll-fail: D settime\n"); return 1;
        }
        t0 = now_ms();
        n = epoll_wait(epfd, out, 1, -1);
        dt = now_ms() - t0;
        wkv("step-D abstime epoll_n", n); wkv("step-D elapsed_ms", (long)dt);
        if (n != 1 || out[0].data.fd != tfd) { w("tfd-epoll-fail: D\n"); return 1; }
        if (dt > worst) worst = dt;
        { uint64_t e = 0; read(tfd, &e, sizeof e); }
    }

    /* step E: PLAIN epoll timeout on an EMPTY interest set — no fd ready and
     * no timerfd, so the wakeup MUST come from the scheduler honouring the
     * timeout deadline, not a fd becoming readable. This is exactly what
     * libwayland's event loop does every idle tick: wl_event_loop_dispatch(
     * loop, ms) -> epoll_wait(epfd, ev, n, ms).
     *
     * The regression this pins: epoll_wait RIP-rewinds and RE-EXECUTES on every
     * wake (to re-check readiness), but the scheduler clears its wake-signal
     * (sleep_deadline_ns) the instant the deadline expires — so the re-executed
     * call recomputed a FRESH `now + timeout` deadline and re-armed forever. A
     * pure-timeout epoll_wait NEVER returned (hung, not just slow), which
     * stalled every idle tick of a real compositor. Fixed by persisting the
     * deadline in a field the scheduler doesn't touch (blocking_deadline_ns). */
    epoll_ctl(epfd, EPOLL_CTL_DEL, tfd, NULL);
    {
        int64_t t1 = now_ms();
        int m = epoll_wait(epfd, out, 1, 120); /* 120ms timeout, empty set */
        int64_t de = now_ms() - t1;
        wkv("step-E plain_n", m);
        wkv("step-E elapsed_ms", (long)de);
        if (m != 0) {
            w("tfd-epoll-fail: E expected-timeout\n");
            return 1;
        }
        if (de < 90 || de > 400) {
            w("tfd-epoll-fail: E timeout not honored at the deadline\n");
            return 1;
        }
    }

    /* step F: the same pure-timeout regression via poll(2) — libwayland's
     * client side (wl_display_dispatch / roundtrip) blocks in poll(), which
     * shares the re-execute-and-recompute hazard (it parks in ~1ms chunks and
     * re-enters the syscall on each). A poll() on a fd set with nothing ready
     * must return 0 at the deadline, not hang. */
    {
        struct pollfd none = { .fd = -1, .events = POLLIN };
        int64_t t1 = now_ms();
        int m = poll(&none, 1, 120);
        int64_t de = now_ms() - t1;
        wkv("step-F poll_n", m);
        wkv("step-F elapsed_ms", (long)de);
        if (m != 0) { w("tfd-epoll-fail: F expected-timeout\n"); return 1; }
        if (de < 90 || de > 400) {
            w("tfd-epoll-fail: F timeout not honored at the deadline\n");
            return 1;
        }
    }

    if (worst > GATE_MS) { w("tfd-epoll-fail: slow\n"); return 1; }
    w("tfd-epoll-ok\n");
    return 0;
}
