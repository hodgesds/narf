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
 *
 * Each armed timer is ~30ms out, so a correct waker lands every step well under
 * the 250ms gate. The pre-fix bug woke step B only on epoll's ~2s park fallback
 * (~2200ms) and hung step C forever — both caught here.
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

    if (worst > GATE_MS) { w("tfd-epoll-fail: slow\n"); return 1; }
    w("tfd-epoll-ok\n");
    return 0;
}
