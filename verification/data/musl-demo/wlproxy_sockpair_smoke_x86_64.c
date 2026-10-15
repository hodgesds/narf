/* AF_UNIX stream forwarder stress, shaped like Firefox's wayland-proxy.
 *
 * Firefox runs its Wayland traffic through an in-process proxy:
 * application <-> proxy <-> compositor, over nonblocking AF_UNIX
 * SOCK_STREAM sockets. The proxy (widget/gtk/wayland/wayland-proxy.cpp,
 * WaylandMessage::Read/Write) forwards each chunk it reads:
 *
 *   recvmsg(4096 bytes + up to 28 SCM_RIGHTS fds,
 *           MSG_CMSG_CLOEXEC | MSG_DONTWAIT)
 *   sendmsg(that chunk + its fds, MSG_DONTWAIT)
 *
 * It treats MSG_CTRUNC as fatal and, if sendmsg writes FEWER bytes than the
 * chunk, only logs "failed to write all data!" and drops the rest. That is
 * safe on Linux because a nonblocking unix_stream_sendmsg of at most one skb
 * is all-or-EAGAIN, and a recvmsg returns at most one rights-carrying skb.
 * If either is violated the stream desynchronises and libwayland-client
 * aborts with "Message length N exceeds limit 4096".
 *
 * Three threads: a writer producing Wayland-framed messages (some with fds)
 * as fast as it can, the proxy forwarding pair A to pair B with exactly the
 * logic above, and a deliberately slow reader that validates framing, the
 * sequence numbers, every payload byte and that each message's fds arrive
 * no later than the message itself.
 *
 * Usage: wlproxy_sockpair_smoke [seconds]   (default 8)
 * Success token: "wlproxy-ok". Failure: "wlproxy-fail-<what>".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATA 4096
#define MAX_FDS 28
#define MAX_MSG 4096

static volatile int g_fail;
static volatile int g_done;
static char g_why[160];
static unsigned long long g_msgs, g_fds, g_short_reads;

static void fail(const char *what) {
    if (!__sync_lock_test_and_set(&g_fail, 1)) {
        snprintf(g_why, sizeof g_why, "%s", what);
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint32_t rng(uint32_t *s) {
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

static uint8_t pattern(uint32_t seq, uint32_t i) {
    return (uint8_t)(seq * 31u + i * 7u + 3u);
}

static void wait_fd(int fd, short ev) {
    struct pollfd p = {fd, ev, 0};
    poll(&p, 1, 50);
}

/* sendmsg(fd, buf[0..len], fds[0..nfds], MSG_DONTWAIT) */
static ssize_t send_chunk(int fd, const uint8_t *buf, size_t len, const int *fds, int nfds,
                          int flags) {
    struct iovec iov = {(void *)buf, len};
    union {
        char b[CMSG_SPACE(sizeof(int) * MAX_FDS)];
        struct cmsghdr align;
    } c;
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(&c, 0, sizeof c);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    if (nfds) {
        m.msg_control = c.b;
        m.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = SOL_SOCKET;
        h->cmsg_type = SCM_RIGHTS;
        h->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
        memcpy(CMSG_DATA(h), fds, sizeof(int) * nfds);
    }
    return sendmsg(fd, &m, flags);
}

/* recvmsg(fd, cap bytes + MAX_FDS fds); returns bytes, fills fds/nfds;
 * -2 on MSG_CTRUNC/too many fds. */
static ssize_t recv_chunk(int fd, uint8_t *buf, size_t cap, int *fds, int *nfds) {
    struct iovec iov = {buf, cap};
    char cbuf[CMSG_LEN(MAX_FDS * sizeof(int32_t))];
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(cbuf, 0, sizeof cbuf);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf;
    m.msg_controllen = sizeof cbuf;
    *nfds = 0;
    ssize_t r = recvmsg(fd, &m, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (r > 0 && (m.msg_flags & (MSG_CTRUNC | MSG_TRUNC))) {
        return -2;
    }
    if (r <= 0) {
        return r;
    }
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h)) {
        if (h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        int k = (int)((h->cmsg_len - CMSG_LEN(0)) / sizeof(int));
        if (*nfds + k > MAX_FDS) {
            return -2;
        }
        memcpy(fds + *nfds, CMSG_DATA(h), sizeof(int) * k);
        *nfds += k;
    }
    return r;
}

struct pairs {
    int app_w, proxy_in, proxy_out, comp_r;
    uint64_t deadline;
};

/* Writer: libwayland-like. Messages are queued into a 4096-byte output
 * buffer and flushed with one sendmsg carrying all queued fds; a short
 * write just advances (libwayland handles it), EAGAIN waits. */
static void *writer(void *arg) {
    struct pairs *p = arg;
    uint32_t s = 0x1234567u, seq = 0;
    int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        fail("writer-open");
        return NULL;
    }
    uint8_t out[MAX_DATA];
    size_t out_len = 0, out_off = 0;
    int out_fds[MAX_FDS], out_nfds = 0;
    while (!g_fail) {
        if (out_off == out_len) {
            out_len = out_off = 0;
            out_nfds = 0;
            if (now_ns() >= p->deadline) {
                break;
            }
            /* Fill the buffer with whole messages. */
            for (;;) {
                uint32_t size = 8 + 4 * (rng(&s) % ((MAX_MSG - 8) / 4 + 1));
                if (rng(&s) % 4) {
                    size = 8 + 4 * (rng(&s) % 64); /* mostly small */
                }
                uint32_t nfds = (rng(&s) % 8 == 0) ? 1 + rng(&s) % 4 : 0;
                if (out_len + size > MAX_DATA || out_nfds + (int)nfds > MAX_FDS) {
                    break;
                }
                uint8_t *m = out + out_len;
                memcpy(m, &seq, 4);
                uint32_t w1 = (size << 16) | nfds;
                memcpy(m + 4, &w1, 4);
                for (uint32_t i = 8; i < size; i++) {
                    m[i] = pattern(seq, i);
                }
                for (uint32_t i = 0; i < nfds; i++) {
                    out_fds[out_nfds++] = devnull;
                }
                out_len += size;
                seq++;
            }
        }
        ssize_t r = send_chunk(p->app_w, out + out_off, out_len - out_off, out_fds, out_nfds,
                               MSG_DONTWAIT | MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                wait_fd(p->app_w, POLLOUT);
                continue;
            }
            fail("writer-sendmsg");
            break;
        }
        if (r == 0) {
            fail("writer-sendmsg-zero");
            break;
        }
        out_off += (size_t)r;
        out_nfds = 0; /* fds ride on the first byte only */
    }
    shutdown(p->app_w, SHUT_WR);
    close(devnull);
    return NULL;
}

/* Proxy: exactly WaylandMessage::Read/Write. */
static void *proxy(void *arg) {
    struct pairs *p = arg;
    uint8_t buf[MAX_DATA];
    int fds[MAX_FDS], nfds = 0;
    ssize_t len = 0;
    while (!g_fail) {
        if (len == 0) {
            ssize_t r = recv_chunk(p->proxy_in, buf, sizeof buf, fds, &nfds);
            if (r == -2) {
                fail("proxy-recvmsg-ctrunc");
                break;
            }
            if (r == 0) {
                break; /* writer done */
            }
            if (r < 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    wait_fd(p->proxy_in, POLLIN);
                    continue;
                }
                fail("proxy-recvmsg");
                break;
            }
            len = r;
        }
        ssize_t w = send_chunk(p->proxy_out, buf, (size_t)len, fds, nfds,
                               MSG_CMSG_CLOEXEC | MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w < 1) {
            if (errno == EAGAIN || errno == EINTR) {
                wait_fd(p->proxy_out, POLLOUT);
                continue;
            }
            fail("proxy-sendmsg");
            break;
        }
        if (w != len) {
            /* The real proxy drops the remainder here: the stream is now
             * desynchronised. */
            char why[96];
            snprintf(why, sizeof why, "proxy-short-sendmsg-%zd-of-%zd", w, len);
            fail(why);
            break;
        }
        for (int i = 0; i < nfds; i++) {
            close(fds[i]);
        }
        nfds = 0;
        len = 0;
    }
    shutdown(p->proxy_out, SHUT_WR);
    return NULL;
}

/* Reader: slow, random-sized reads; validates everything. */
static void *reader(void *arg) {
    struct pairs *p = arg;
    static uint8_t acc[2 * MAX_DATA + 8192];
    size_t acc_len = 0;
    uint32_t s = 0x9e3779b9u, expect = 0;
    unsigned long long fds_have = 0;
    while (!g_fail) {
        if (rng(&s) % 4 == 0) {
            usleep(200 + rng(&s) % 800); /* let the rings fill */
        }
        uint8_t chunk[MAX_DATA];
        size_t cap = 1 + rng(&s) % MAX_DATA;
        int fds[MAX_FDS], nfds = 0;
        ssize_t r = recv_chunk(p->comp_r, chunk, cap, fds, &nfds);
        if (r == -2) {
            fail("reader-recvmsg-ctrunc");
            break;
        }
        if (r == 0) {
            if (acc_len != 0) {
                fail("reader-trailing-partial-message");
            }
            break;
        }
        if (r < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                wait_fd(p->comp_r, POLLIN);
                continue;
            }
            fail("reader-recvmsg");
            break;
        }
        if ((size_t)r < cap) {
            g_short_reads++;
        }
        for (int i = 0; i < nfds; i++) {
            close(fds[i]);
        }
        fds_have += (unsigned)nfds;
        memcpy(acc + acc_len, chunk, (size_t)r);
        acc_len += (size_t)r;
        size_t off = 0;
        while (acc_len - off >= 8) {
            uint32_t seq, w1;
            memcpy(&seq, acc + off, 4);
            memcpy(&w1, acc + off + 4, 4);
            uint32_t size = w1 >> 16, mfds = w1 & 0xffff;
            if (size > MAX_MSG || size < 8 || (size & 3)) {
                char why[96];
                snprintf(why, sizeof why, "reader-message-length-%u-exceeds-limit", size);
                fail(why);
                return NULL;
            }
            if (seq != expect) {
                fail("reader-sequence-gap");
                return NULL;
            }
            if (acc_len - off < size) {
                break;
            }
            for (uint32_t i = 8; i < size; i++) {
                if (acc[off + i] != pattern(seq, i)) {
                    fail("reader-payload-corrupt");
                    return NULL;
                }
            }
            /* libwayland demarshals a message's fds from the fds already
             * received: they must not arrive after the message. */
            if (fds_have < mfds) {
                fail("reader-fds-late");
                return NULL;
            }
            fds_have -= mfds;
            g_fds += mfds;
            g_msgs++;
            expect++;
            off += size;
        }
        memmove(acc, acc + off, acc_len - off);
        acc_len -= off;
    }
    if (!g_fail && fds_have != 0) {
        fail("reader-extra-fds");
    }
    return NULL;
}

int main(int argc, char **argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 8;
    int a[2], b[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, a) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, b)) {
        printf("wlproxy-fail-socketpair\n");
        return 1;
    }
    struct pairs p = {a[0], a[1], b[0], b[1], now_ns() + (uint64_t)secs * 1000000000ull};
    pthread_t tw, tp, tr;
    pthread_create(&tr, NULL, reader, &p);
    pthread_create(&tp, NULL, proxy, &p);
    pthread_create(&tw, NULL, writer, &p);
    pthread_join(tw, NULL);
    pthread_join(tp, NULL);
    pthread_join(tr, NULL);
    g_done = 1;
    if (g_fail) {
        printf("wlproxy-fail-%s after %llu msgs\n", g_why, g_msgs);
        return 1;
    }
    if (g_msgs == 0) {
        printf("wlproxy-fail-no-traffic\n");
        return 1;
    }
    printf("wlproxy: %llu msgs, %llu fds, %llu short reads\n", g_msgs, g_fds, g_short_reads);
    printf("wlproxy-ok\n");
    return 0;
}
