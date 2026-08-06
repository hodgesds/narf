/* polltmo_hammer — timerfd/epoll churn + pure-timeout poll/epoll hammer.
 *
 * Regression pin for a load-dependent kernel slab double-free that
 * tfd_epoll_smoke tripped intermittently: after its timerfd-in-epoll
 * steps, the PURE-TIMEOUT windows (epoll_wait on an empty interest set,
 * poll on {fd = -1}) died inside the kernel with
 *
 *   slab: double free of block ... (class 32 B)
 *
 * in poll_scan's Vec drop, at a rate of roughly one boot in a few under
 * host load. One 120 ms window per boot is a coin flip; this case runs
 * the whole sequence — timerfd create/arm/fire/read via poll AND epoll,
 * EPOLL_CTL_DEL of the armed fd, then the two pure-timeout windows —
 * dozens of times across 4 concurrent processes, so a kernel with that
 * class of bug panics reliably instead of flakily.
 */
#define _GNU_SOURCE 1
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void w(const char *s) { write(1, s, strlen(s)); }

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define NPROC 8
#define ITERS 150
#define PERIOD_MS 6   /* timerfd arm distance */
#define TMO_MS 11     /* pure-timeout window */

static void arm_rel(int tfd) {
    struct itimerspec its = {0};
    its.it_value.tv_nsec = PERIOD_MS * 1000000L;
    timerfd_settime(tfd, 0, &its, NULL);
}

static int child_main(void) {
    for (int i = 0; i < ITERS; i++) {
        int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (tfd < 0) return 2;
        int epfd = epoll_create1(0);
        if (epfd < 0) return 3;
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = tfd };
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) != 0) return 4;

        /* timerfd wake via plain poll (tfd step A) */
        arm_rel(tfd);
        struct pollfd pfd = { .fd = tfd, .events = POLLIN };
        if (poll(&pfd, 1, 3000) != 1) return 5;
        { uint64_t e; read(tfd, &e, sizeof e); }

        /* timerfd wake via epoll_wait finite timeout (tfd step B) */
        arm_rel(tfd);
        struct epoll_event out[1];
        if (epoll_wait(epfd, out, 1, 3000) != 1) return 6;
        { uint64_t e; read(tfd, &e, sizeof e); }

        /* timerfd wake via epoll_wait(-1) (tfd step C) */
        arm_rel(tfd);
        if (epoll_wait(epfd, out, 1, -1) != 1) return 7;
        { uint64_t e; read(tfd, &e, sizeof e); }

        /* re-arm, DEL the armed fd, then the pure-timeout windows the
         * panic struck in (tfd steps E/F). The timer stays armed across
         * the DEL, so its expiry lands while nothing references it. */
        arm_rel(tfd);
        epoll_ctl(epfd, EPOLL_CTL_DEL, tfd, NULL);

        int64_t t0 = now_ms();
        int n = epoll_wait(epfd, out, 1, TMO_MS); /* empty interest set */
        if (n != 0) return 8;
        if (now_ms() - t0 > 4000) return 9;

        struct pollfd none = { .fd = -1, .events = POLLIN };
        t0 = now_ms();
        n = poll(&none, 1, TMO_MS);
        if (n != 0) return 10;
        if (now_ms() - t0 > 4000) return 11;

        close(epfd);
        close(tfd);
    }
    return 0;
}

int main(void) {
    pid_t kids[NPROC];
    for (int i = 0; i < NPROC; i++) {
        pid_t p = fork();
        if (p < 0) { w("polltmo-fail: fork\n"); return 1; }
        if (p == 0) _exit(child_main());
        kids[i] = p;
    }
    int bad = 0;
    for (int i = 0; i < NPROC; i++) {
        int st = 0;
        if (waitpid(kids[i], &st, 0) != kids[i]) bad = 100 + i;
        else if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            char buf[64];
            snprintf(buf, sizeof buf, "polltmo-fail: child %d status %d\n", i,
                     WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            w(buf);
            bad = 1;
        }
    }
    if (bad) return 1;
    w("polltmo-ok\n");
    return 0;
}
