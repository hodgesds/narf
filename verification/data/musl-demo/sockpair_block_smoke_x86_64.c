// A blocking AF_UNIX stream send queues the whole payload before returning.
//
// Linux `unix_stream_sendmsg` (net/unix/af_unix.c) loops over the payload,
// and `sock_alloc_send_pskb` / `sock_wait_for_wmem` (net/core/sock.c) sleep
// for send-buffer space between units. The send returns early only when:
//   - a signal ends the wait: the bytes already queued, or, with nothing
//     queued, `sock_intr_errno(timeo)` = -ERESTARTSYS (SA_RESTART restarts
//     it) for an infinite timeout and -EINTR for a finite SO_SNDTIMEO;
//   - SO_SNDTIMEO expires: the bytes queued, or -EAGAIN with nothing queued;
//   - the peer goes away: the bytes queued with NO SIGPIPE. With nothing
//     queued, a send that finds the peer already gone is -EPIPE plus SIGPIPE
//     (unless MSG_NOSIGNAL; `out_pipe: if (!sent && ...) send_sig(SIGPIPE)`),
//     but one woken from its wait gets `sock_error`'s ECONNRESET (the peer
//     closed with unread data: `unix_release_sock` sets `sk_err`) and no
//     SIGPIPE. The parked sender consumes that ECONNRESET; otherwise
//     SO_ERROR reports it once.
// SCM_RIGHTS ride on the first unit only (`unix_scm_to_skb(.., !fds_sent)`),
// so the receiver gets them with the first byte and never again.
//
// NARF returned a short count from a blocking send as soon as the ring was
// full, so a writer that trusted a blocking send (most of them) silently
// lost the tail; then, once it waited, a signal turned the queued prefix
// into EINTR. send(2), write(2) and sendmsg(2) are each checked.
//
// Success token "sockpair-block-ok"; failures print "sockpair-block-fail".
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BIG (1 << 20)
#define SMALL 4096
// Long enough for the sender to fill the default 208 KiB sndbuf and park.
#define SETTLE_US 400000

enum how { VIA_SEND, VIA_WRITE, VIA_SENDMSG };
static const char *how_name[] = {"send", "write", "sendmsg"};

static int failed;
static unsigned char payload[BIG];
static volatile sig_atomic_t g_usr1, g_pipe;

static void on_usr1(int s) {
    (void)s;
    g_usr1++;
}
static void on_pipe(int s) {
    (void)s;
    g_pipe++;
}
static void on_alrm(int s) {
    (void)s;
    static const char m[] = "sockpair-block-fail: case timed out (a send or read never returned)\n";
    (void)!write(1, m, sizeof m - 1);
    _exit(1);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static unsigned char pat(size_t i) { return (unsigned char)(i * 131 + (i >> 12)); }

static void fail(const char *ctx, const char *what, long v) {
    printf("sockpair-block-fail: %s: %s (%ld)\n", ctx, what, v);
    fflush(stdout);
    failed = 1;
}

static void handler(int sig, void (*fn)(int), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fn;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

static void pair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("sockpair-block-fail: socketpair errno=%d\n", errno);
        exit(1);
    }
}

// One blocking send of `len` bytes of `payload` (+ optional SCM_RIGHTS).
static ssize_t do_send(int fd, enum how how, size_t len, int flags, int pass_fd) {
    if (how == VIA_SEND)
        return send(fd, payload, len, flags);
    if (how == VIA_WRITE)
        return write(fd, payload, len);
    struct iovec iov = {payload, len};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctl;
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    if (pass_fd >= 0) {
        memset(&ctl, 0, sizeof ctl);
        mh.msg_control = ctl.buf;
        mh.msg_controllen = sizeof ctl.buf;
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &pass_fd, sizeof(int));
    }
    return sendmsg(fd, &mh, flags);
}

struct sender {
    pthread_t th;
    int fd, flags, pass_fd;
    enum how how;
    size_t len;
    ssize_t ret;
    int err;
    int usr1_at_return, pipe_at_return;
    long t_end;
    volatile int done;
};

static void *sender_main(void *p) {
    struct sender *s = p;
    s->ret = do_send(s->fd, s->how, s->len, s->flags, s->pass_fd);
    s->err = errno;
    s->usr1_at_return = g_usr1;
    s->pipe_at_return = g_pipe;
    s->t_end = now_ms();
    s->done = 1;
    return NULL;
}

static void start(struct sender *s, int fd, enum how how, size_t len, int flags, int pass_fd) {
    memset(s, 0, sizeof *s);
    s->fd = fd;
    s->how = how;
    s->len = len;
    s->flags = flags;
    s->pass_fd = pass_fd;
    pthread_create(&s->th, NULL, sender_main, s);
}

// Read whatever is queued without blocking, checking it continues the
// pattern at `*off`. Returns the byte count.
static size_t drain(const char *ctx, int fd, size_t *off) {
    static unsigned char buf[65536];
    size_t got = 0;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0)
            break;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != pat(*off + i)) {
                fail(ctx, "received byte differs from the payload at offset", (long)(*off + i));
                *off += n;
                return got + n;
            }
        }
        *off += n;
        got += n;
    }
    return got;
}

// Fill `fd`'s send buffer with non-blocking sends until EAGAIN.
static size_t fill(int fd) {
    size_t total = 0;
    while (send(fd, payload + (total % (BIG - SMALL)), SMALL, MSG_DONTWAIT) == SMALL)
        total += SMALL;
    return total;
}

// 1. A blocking send larger than the send buffer returns the full length
// while a reader drains slowly, and the reader sees identical bytes.
static void test_full(enum how how) {
    char ctx[64];
    snprintf(ctx, sizeof ctx, "full %s", how_name[how]);
    int sv[2];
    pair(sv);
    struct sender s;
    start(&s, sv[0], how, BIG, 0, -1);
    static unsigned char buf[SMALL];
    size_t off = 0;
    while (off < BIG) {
        ssize_t n = read(sv[1], buf, sizeof buf);
        if (n <= 0) {
            fail(ctx, "reader read failed before the whole payload, errno", n < 0 ? errno : 0);
            break;
        }
        for (ssize_t i = 0; i < n; i++)
            if (buf[i] != pat(off + i)) {
                fail(ctx, "reader byte differs at offset", (long)(off + i));
                n = 0;
                break;
            }
        if (n == 0)
            break;
        off += n;
        if ((off / SMALL) % 8 == 0)
            usleep(1000); // slow reader
    }
    pthread_join(s.th, NULL);
    if (s.ret != BIG)
        fail(ctx, "blocking 1 MiB send returned", s.ret < 0 ? -s.err : s.ret);
    close(sv[0]);
    close(sv[1]);
}

// 2a. A signal interrupting a blocked send after some progress returns the
// bytes queued, with or without SA_RESTART; the handler has already run.
static void test_signal_partial(enum how how, int sa_flags) {
    char ctx[64];
    snprintf(ctx, sizeof ctx, "signal partial %s%s", how_name[how],
             sa_flags ? " SA_RESTART" : "");
    handler(SIGUSR1, on_usr1, sa_flags);
    g_usr1 = 0;
    int sv[2];
    pair(sv);
    struct sender s;
    start(&s, sv[0], how, BIG, 0, -1);
    usleep(SETTLE_US);
    if (s.done)
        fail(ctx, "blocking send returned before any reader or signal, ret", s.ret);
    pthread_kill(s.th, SIGUSR1);
    pthread_join(s.th, NULL);
    if (s.ret <= 0 || s.ret >= BIG)
        fail(ctx, "interrupted send did not return a partial count, ret", s.ret < 0 ? -s.err : s.ret);
    if (s.usr1_at_return != 1)
        fail(ctx, "handler had not run when the send returned, count", s.usr1_at_return);
    size_t off = 0;
    size_t got = drain(ctx, sv[1], &off);
    if (s.ret > 0 && got != (size_t)s.ret)
        fail(ctx, "peer holds a different byte count than the send returned", (long)got);
    close(sv[0]);
    close(sv[1]);
}

// 2b. With nothing queued, the signal gives EINTR without SA_RESTART; with
// SA_RESTART the send restarts and completes once the peer drains.
static void test_signal_nothing(int sa_flags) {
    char ctx[64];
    snprintf(ctx, sizeof ctx, "signal nothing-sent%s", sa_flags ? " SA_RESTART" : "");
    handler(SIGUSR1, on_usr1, sa_flags);
    g_usr1 = 0;
    int sv[2];
    pair(sv);
    size_t filled = fill(sv[0]);
    struct sender s;
    start(&s, sv[0], VIA_SEND, SMALL, 0, -1);
    usleep(SETTLE_US);
    if (s.done)
        fail(ctx, "send into a full buffer returned at once, ret", s.ret < 0 ? -s.err : s.ret);
    pthread_kill(s.th, SIGUSR1);
    if (!sa_flags) {
        pthread_join(s.th, NULL);
        if (s.ret != -1 || s.err != EINTR)
            fail(ctx, "expected -1/EINTR, got", s.ret < 0 ? -s.err : s.ret);
    } else {
        usleep(SETTLE_US);
        if (s.done)
            fail(ctx, "SA_RESTART send returned instead of restarting, ret",
                 s.ret < 0 ? -s.err : s.ret);
        // Drain everything the fill queued; the restarted send then fits.
        static unsigned char buf[65536];
        size_t got = 0;
        while (got < filled) {
            ssize_t n = read(sv[1], buf, sizeof buf);
            if (n <= 0)
                break;
            got += n;
        }
        pthread_join(s.th, NULL);
        if (s.ret != SMALL)
            fail(ctx, "restarted send returned", s.ret < 0 ? -s.err : s.ret);
    }
    if (s.usr1_at_return != 1)
        fail(ctx, "handler count when the send returned", s.usr1_at_return);
    close(sv[0]);
    close(sv[1]);
}

// 2c. A signal ending a FINITE SO_SNDTIMEO wait with nothing queued is EINTR
// even under SA_RESTART (`sock_intr_errno`).
static void test_signal_timeo_nothing(void) {
    const char *ctx = "signal nothing-sent SO_SNDTIMEO SA_RESTART";
    handler(SIGUSR1, on_usr1, SA_RESTART);
    g_usr1 = 0;
    int sv[2];
    pair(sv);
    struct timeval tv = {5, 0};
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    fill(sv[0]);
    struct sender s;
    start(&s, sv[0], VIA_SEND, SMALL, 0, -1);
    usleep(SETTLE_US);
    long t0 = now_ms();
    pthread_kill(s.th, SIGUSR1);
    pthread_join(s.th, NULL);
    if (s.ret != -1 || s.err != EINTR)
        fail(ctx, "expected -1/EINTR, got", s.ret < 0 ? -s.err : s.ret);
    if (s.t_end - t0 > 2000)
        fail(ctx, "send outlived the signal by ms", s.t_end - t0);
    close(sv[0]);
    close(sv[1]);
}

// 3. SO_SNDTIMEO expiry returns the bytes queued, or EAGAIN with none, and
// only after the timeout has run.
static void test_sndtimeo(enum how how) {
    char ctx[64];
    snprintf(ctx, sizeof ctx, "SO_SNDTIMEO %s", how_name[how]);
    int sv[2];
    pair(sv);
    struct timeval tv = {0, 300000};
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    long t0 = now_ms();
    ssize_t r = do_send(sv[0], how, BIG, 0, -1);
    long waited = now_ms() - t0;
    if (r <= 0 || r >= BIG)
        fail(ctx, "timed-out send did not return a partial count, ret", r < 0 ? -errno : r);
    if (waited < 250)
        fail(ctx, "partial send returned before SO_SNDTIMEO, ms", waited);
    size_t off = 0;
    size_t got = drain(ctx, sv[1], &off);
    if (r > 0 && got != (size_t)r)
        fail(ctx, "peer holds a different byte count than the send returned", (long)got);
    fill(sv[0]);
    t0 = now_ms();
    r = do_send(sv[0], how, SMALL, 0, -1);
    int e = errno;
    waited = now_ms() - t0;
    if (r != -1 || e != EAGAIN)
        fail(ctx, "timed-out send with nothing queued: expected -1/EAGAIN, got", r < 0 ? -e : r);
    if (waited < 250)
        fail(ctx, "EAGAIN came before SO_SNDTIMEO, ms", waited);
    close(sv[0]);
    close(sv[1]);
}

// 4. The peer closing mid-send gives the partial count without SIGPIPE; the
// next send is EPIPE with SIGPIPE already delivered (none with MSG_NOSIGNAL).
static void test_peer_close(enum how how) {
    char ctx[64];
    snprintf(ctx, sizeof ctx, "peer close %s", how_name[how]);
    g_pipe = 0;
    int sv[2];
    pair(sv);
    struct sender s;
    start(&s, sv[0], how, BIG, 0, -1);
    usleep(SETTLE_US);
    if (s.done)
        fail(ctx, "blocking send returned before the peer closed, ret", s.ret);
    long t_close = now_ms();
    close(sv[1]);
    pthread_join(s.th, NULL);
    if (s.ret <= 0 || s.ret >= BIG)
        fail(ctx, "send cut off by the peer did not return a partial count, ret",
             s.ret < 0 ? -s.err : s.ret);
    if (s.t_end < t_close)
        fail(ctx, "send returned before the peer closed, ms early", t_close - s.t_end);
    if (s.pipe_at_return != 0)
        fail(ctx, "partial send raised SIGPIPE, count", s.pipe_at_return);
    int soerr = -1;
    socklen_t sl = sizeof soerr;
    getsockopt(sv[0], SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr != 0)
        fail(ctx, "SO_ERROR after the woken send consumed the reset", soerr);
    ssize_t r = do_send(sv[0], how, SMALL, 0, -1);
    int e = errno;
    int pipes = g_pipe;
    if (r != -1 || e != EPIPE)
        fail(ctx, "send after the peer closed: expected -1/EPIPE, got", r < 0 ? -e : r);
    if (pipes != 1)
        fail(ctx, "SIGPIPE count when EPIPE returned", pipes);
    if (how != VIA_WRITE) {
        r = do_send(sv[0], how, SMALL, MSG_NOSIGNAL, -1);
        e = errno;
        if (r != -1 || e != EPIPE)
            fail(ctx, "MSG_NOSIGNAL send after close: expected -1/EPIPE, got", r < 0 ? -e : r);
        if (g_pipe != 1)
            fail(ctx, "MSG_NOSIGNAL still raised SIGPIPE, count", g_pipe);
    }
    close(sv[0]);
}

// 4b. A send parked with nothing queued, woken by the peer closing (with
// unread data, necessarily: that is why it waited), fails ECONNRESET with no
// SIGPIPE; the next send finds SEND_SHUTDOWN first: EPIPE + SIGPIPE.
static void test_peer_close_nothing(void) {
    const char *ctx = "peer close nothing-sent";
    g_pipe = 0;
    int sv[2];
    pair(sv);
    fill(sv[0]);
    struct sender s;
    start(&s, sv[0], VIA_SEND, SMALL, 0, -1);
    usleep(SETTLE_US);
    if (s.done)
        fail(ctx, "send into a full buffer returned at once, ret", s.ret < 0 ? -s.err : s.ret);
    close(sv[1]);
    pthread_join(s.th, NULL);
    if (s.ret != -1 || s.err != ECONNRESET)
        fail(ctx, "expected -1/ECONNRESET, got", s.ret < 0 ? -s.err : s.ret);
    if (s.pipe_at_return != 0)
        fail(ctx, "woken send raised SIGPIPE, count", s.pipe_at_return);
    ssize_t r = send(sv[0], payload, SMALL, 0);
    int e = errno;
    int pipes = g_pipe;
    if (r != -1 || e != EPIPE)
        fail(ctx, "next send: expected -1/EPIPE, got", r < 0 ? -e : r);
    if (pipes != 1)
        fail(ctx, "SIGPIPE count when the next send's EPIPE returned", pipes);
    close(sv[0]);
}

// 4c. With no sender waiting, the reset the closing peer leaves is reported
// once by SO_ERROR; sends see SEND_SHUTDOWN first (EPIPE + SIGPIPE).
static void test_peer_close_reset(void) {
    const char *ctx = "peer close with unread data";
    g_pipe = 0;
    int sv[2];
    pair(sv);
    if (send(sv[0], payload, SMALL, 0) != SMALL)
        fail(ctx, "seed send failed, errno", errno);
    close(sv[1]);
    ssize_t r = send(sv[0], payload, SMALL, 0);
    int e = errno;
    if (r != -1 || e != EPIPE)
        fail(ctx, "send: expected -1/EPIPE, got", r < 0 ? -e : r);
    if (g_pipe != 1)
        fail(ctx, "SIGPIPE count when EPIPE returned", g_pipe);
    int soerr = -1;
    socklen_t sl = sizeof soerr;
    getsockopt(sv[0], SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr != ECONNRESET)
        fail(ctx, "first SO_ERROR", soerr);
    soerr = -1;
    getsockopt(sv[0], SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr != 0)
        fail(ctx, "second SO_ERROR", soerr);
    close(sv[0]);
}

// 5. SCM_RIGHTS on a blocking 1 MiB sendmsg arrive once, with the first byte.
static void test_rights(void) {
    const char *ctx = "SCM_RIGHTS 1 MiB";
    int sv[2];
    pair(sv);
    int p[2];
    if (pipe(p) != 0) {
        fail(ctx, "pipe errno", errno);
        return;
    }
    struct sender s;
    start(&s, sv[0], VIA_SENDMSG, BIG, 0, p[0]);
    static unsigned char buf[65536];
    size_t off = 0;
    int fds_seen = 0, recvs = 0;
    while (off < BIG) {
        union {
            char b[CMSG_SPACE(4 * sizeof(int))];
            struct cmsghdr align;
        } ctl;
        struct iovec iov = {buf, sizeof buf};
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = ctl.b;
        mh.msg_controllen = sizeof ctl.b;
        ssize_t n = recvmsg(sv[1], &mh, 0);
        if (n <= 0) {
            fail(ctx, "recvmsg failed before the whole payload, errno", n < 0 ? errno : 0);
            break;
        }
        if (mh.msg_flags & MSG_CTRUNC)
            fail(ctx, "MSG_CTRUNC at offset", (long)off);
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
                continue;
            int nfd = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (int i = 0; i < nfd; i++) {
                int f;
                memcpy(&f, CMSG_DATA(c) + i * sizeof(int), sizeof f);
                close(f);
            }
            if (off != 0)
                fail(ctx, "SCM_RIGHTS arrived away from the first byte, offset", (long)off);
            fds_seen += nfd;
        }
        if (off == 0 && fds_seen != 1)
            fail(ctx, "first recvmsg did not carry exactly the one fd, got", fds_seen);
        for (ssize_t i = 0; i < n; i++)
            if (buf[i] != pat(off + i)) {
                fail(ctx, "received byte differs at offset", (long)(off + i));
                break;
            }
        off += n;
        if (++recvs % 4 == 0)
            usleep(1000); // slow reader
    }
    pthread_join(s.th, NULL);
    if (s.ret != BIG)
        fail(ctx, "blocking 1 MiB sendmsg with SCM_RIGHTS returned", s.ret < 0 ? -s.err : s.ret);
    if (fds_seen != 1)
        fail(ctx, "fds received in total", fds_seen);
    close(p[0]);
    close(p[1]);
    close(sv[0]);
    close(sv[1]);
}

// Run one case in a child of its own (fresh threads, handlers and
// watchdog), so a case that hangs or crashes is reported and the rest
// still run.
static void run_case(const char *name, void (*fn)(int), int arg) {
    printf("sockpair-block: %s\n", name);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        handler(SIGPIPE, on_pipe, 0);
        handler(SIGALRM, on_alrm, 0);
        alarm(30);
        fn(arg);
        fflush(stdout);
        _exit(failed);
    }
    int st = 0;
    if (c < 0 || waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        if (c > 0 && WIFSIGNALED(st))
            printf("sockpair-block-fail: %s: killed by signal %d\n", name, WTERMSIG(st));
        failed = 1;
    }
}

static void case_full(int h) { test_full(h); }
static void case_signal_partial(int h) { test_signal_partial(h, 0); }
static void case_signal_partial_restart(int h) { test_signal_partial(h, SA_RESTART); }
static void case_signal_nothing(int sa) { test_signal_nothing(sa); }
static void case_signal_timeo_nothing(int u) { (void)u; test_signal_timeo_nothing(); }
static void case_sndtimeo(int h) { test_sndtimeo(h); }
static void case_peer_close(int h) { test_peer_close(h); }
static void case_peer_close_nothing(int u) { (void)u; test_peer_close_nothing(); }
static void case_peer_close_reset(int u) { (void)u; test_peer_close_reset(); }
static void case_rights(int u) { (void)u; test_rights(); }

int main(void) {
    for (size_t i = 0; i < BIG; i++)
        payload[i] = pat(i);
    setvbuf(stdout, NULL, _IOLBF, 0);
    char name[64];
    for (int h = VIA_SEND; h <= VIA_SENDMSG; h++) {
        snprintf(name, sizeof name, "full %s", how_name[h]);
        run_case(name, case_full, h);
    }
    for (int h = VIA_SEND; h <= VIA_SENDMSG; h++) {
        snprintf(name, sizeof name, "signal partial %s", how_name[h]);
        run_case(name, case_signal_partial, h);
        snprintf(name, sizeof name, "signal partial %s SA_RESTART", how_name[h]);
        run_case(name, case_signal_partial_restart, h);
    }
    run_case("signal nothing-sent", case_signal_nothing, 0);
    run_case("signal nothing-sent SA_RESTART", case_signal_nothing, SA_RESTART);
    run_case("signal nothing-sent SO_SNDTIMEO SA_RESTART", case_signal_timeo_nothing, 0);
    for (int h = VIA_SEND; h <= VIA_SENDMSG; h++) {
        snprintf(name, sizeof name, "SO_SNDTIMEO %s", how_name[h]);
        run_case(name, case_sndtimeo, h);
    }
    for (int h = VIA_SEND; h <= VIA_SENDMSG; h++) {
        snprintf(name, sizeof name, "peer close %s", how_name[h]);
        run_case(name, case_peer_close, h);
    }
    run_case("peer close nothing-sent", case_peer_close_nothing, 0);
    run_case("peer close with unread data", case_peer_close_reset, 0);
    run_case("SCM_RIGHTS 1 MiB", case_rights, 0);

    if (failed) {
        printf("sockpair-block-fail: see above\n");
        return 1;
    }
    printf("sockpair-block-ok\n");
    return 0;
}
