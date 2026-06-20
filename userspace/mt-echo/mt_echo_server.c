/* mt_echo_server — multithreaded SO_REUSEPORT TCP echo server.
 *
 * PURPOSE
 * -------
 * A network workload that consumes RX traffic IN PARALLEL across CPU
 * cores, so a multi-queue virtio-net NIC + RSS can demonstrate both
 * throughput AND latency scaling. Single-threaded redis cannot show
 * this: every connection lands on one core, so one RX queue does all
 * the work and extra queues sit idle. Here each worker thread opens
 * its OWN listening socket with SO_REUSEPORT on the SAME port; the
 * kernel (or RSS, when steered by the NIC) hashes incoming
 * connections across the per-thread listeners, so different flows are
 * served by different threads on different cores in parallel.
 *
 * MODEL
 * -----
 *   - N worker threads (N from argv[2] or the MT_ECHO_THREADS env var,
 *     default 4).
 *   - Each thread: socket() -> SO_REUSEPORT + SO_REUSEADDR ->
 *     bind(0.0.0.0:port) -> listen() -> its OWN epoll loop.
 *   - The epoll loop is edge-light level-triggered: it accepts new
 *     connections (its listen fd) and services readable client fds.
 *   - Protocol: read up to REQ_MAX bytes, write a fixed RESP back.
 *     This is an echo-ish/tiny-reply server: the per-request work is
 *     one read + one write, no parsing, no global lock, no allocation
 *     on the hot path. The bottleneck is the network + scheduler, by
 *     design.
 *
 * READINESS MARKER
 * ----------------
 * Once all N listeners are bound+listening, the main thread prints
 *   "mt-echo: listening port=<P> threads=<N>"
 * on stdout (and flushes). A harness (xtask, mirroring the redis
 * "Ready to accept connections" probe) waits for this line before it
 * starts the load generator.
 *
 * BUILD
 * -----
 *   make            # fully static musl ELF placed for NARF's user VA
 *   ./build.sh      # same, with file/ldd verification
 *
 * USAGE
 * -----
 *   mt_echo_server [PORT] [THREADS]
 *   PORT    default 7000   (or MT_ECHO_PORT)
 *   THREADS default 4      (or MT_ECHO_THREADS)
 *
 * NARF NOTE
 * ---------
 * Built -static -no-pie and placed at -Ttext-segment=0x8000001000 so
 * the PT_LOAD segments land in PML4[1] where NARF's user range lives
 * (same constraint hello_musl_x86_64 satisfies). See build.sh.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define MAX_EVENTS 256
#define REQ_MAX 256
/* Fixed tiny reply. Keep small so the wire/scheduler dominate. */
static const char RESP[] = "OK\n";
#define RESP_LEN (sizeof(RESP) - 1)

/* Put an fd in non-blocking mode. REQUIRED with epoll: the listener
 * and client sockets must never block in accept()/read(), or a worker
 * stalls its whole epoll loop after draining the backlog. */
static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int g_port = 7000;
static int g_threads = 4;

/* Count of listeners that have successfully bound+listened, so the
 * main thread can print the readiness marker only once ALL workers
 * are actually accepting. */
static pthread_mutex_t g_ready_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_ready_cv = PTHREAD_COND_INITIALIZER;
static int g_ready_count = 0;
static int g_failed = 0;

static void die(const char *what) {
    /* Use raw write: this runs under NARF where stdio buffering on a
     * fault path can be lost. */
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "mt-echo: FATAL %s: errno=%d\n", what, errno);
    if (n > 0) (void)write(2, buf, (size_t)n);
    pthread_mutex_lock(&g_ready_lock);
    g_failed = 1;
    pthread_cond_broadcast(&g_ready_cv);
    pthread_mutex_unlock(&g_ready_lock);
    pthread_exit(NULL);
}

static int make_listener(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    /* SO_REUSEPORT is the whole point: many listeners, one port, the
     * kernel/NIC steers distinct flows to distinct sockets. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        /* Older kernels / partial stacks: fall back to REUSEADDR only.
         * Still binds, but without per-flow steering. Report once. */
        static int warned = 0;
        if (!warned) {
            warned = 1;
            const char *m = "mt-echo: WARN SO_REUSEPORT unsupported; flow steering disabled\n";
            (void)write(2, m, strlen(m));
        }
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* Low latency: disable Nagle so the tiny reply goes out immediately. */
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); /* 0.0.0.0 — off-box reachable */
    addr.sin_port = htons((uint16_t)g_port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 1024) < 0) {
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void set_client_opts(int fd) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    (void)set_nonblock(fd);
}

/* Serve one ready client fd. Returns 0 to keep, -1 to drop. */
static int serve_client(int fd) {
    char buf[REQ_MAX];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r > 0) {
            /* Tiny fixed reply. One write; loop on partials. */
            size_t off = 0;
            while (off < RESP_LEN) {
                ssize_t w = write(fd, RESP + off, RESP_LEN - off);
                if (w > 0) {
                    off += (size_t)w;
                } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break; /* socket buffer full; client will re-drive us */
                } else {
                    return -1;
                }
            }
            /* Drain only one request per readiness event to stay fair
             * across connections; epoll will re-notify if more is
             * pending (level-triggered). */
            return 0;
        } else if (r == 0) {
            return -1; /* peer closed */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* nothing more right now */
        } else if (errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
}

static void *worker(void *arg) {
    long idx = (long)arg;
    (void)idx;

    int lfd = make_listener();
    if (lfd < 0) die("listener");

    int ep = epoll_create1(0);
    if (ep < 0) die("epoll_create1");

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = lfd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev) < 0) die("epoll_ctl listen");

    /* Signal readiness now that THIS worker is listening. */
    pthread_mutex_lock(&g_ready_lock);
    g_ready_count++;
    pthread_cond_broadcast(&g_ready_cv);
    pthread_mutex_unlock(&g_ready_lock);

    struct epoll_event events[MAX_EVENTS];
    for (;;) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("epoll_wait");
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == lfd) {
                /* Accept as many as are queued. */
                for (;;) {
                    int c = accept(lfd, NULL, NULL);
                    if (c < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                        break;
                    }
                    set_client_opts(c);
                    struct epoll_event cev;
                    memset(&cev, 0, sizeof(cev));
                    cev.events = EPOLLIN;
                    cev.data.fd = c;
                    if (epoll_ctl(ep, EPOLL_CTL_ADD, c, &cev) < 0) {
                        close(c);
                    }
                }
            } else {
                if ((events[i].events & (EPOLLHUP | EPOLLERR)) ||
                    serve_client(fd) < 0) {
                    epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
                    close(fd);
                }
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *pe = getenv("MT_ECHO_PORT");
    const char *te = getenv("MT_ECHO_THREADS");
    if (pe) g_port = atoi(pe);
    if (te) g_threads = atoi(te);
    if (argc > 1) g_port = atoi(argv[1]);
    if (argc > 2) g_threads = atoi(argv[2]);
    if (g_port <= 0 || g_port > 65535) g_port = 7000;
    if (g_threads <= 0) g_threads = 4;
    if (g_threads > 256) g_threads = 256;

    pthread_t *tids = calloc((size_t)g_threads, sizeof(pthread_t));
    if (!tids) {
        const char *m = "mt-echo: FATAL calloc\n";
        (void)write(2, m, strlen(m));
        return 1;
    }

    for (long i = 0; i < g_threads; i++) {
        if (pthread_create(&tids[i], NULL, worker, (void *)i) != 0) {
            const char *m = "mt-echo: FATAL pthread_create\n";
            (void)write(2, m, strlen(m));
            return 1;
        }
    }

    /* Wait until ALL workers are listening (or one failed), then emit
     * the single readiness marker the harness greps for. */
    pthread_mutex_lock(&g_ready_lock);
    while (g_ready_count < g_threads && !g_failed) {
        pthread_cond_wait(&g_ready_cv, &g_ready_lock);
    }
    int failed = g_failed;
    pthread_mutex_unlock(&g_ready_lock);

    if (failed) {
        const char *m = "mt-echo: FATAL a worker failed to bind\n";
        (void)write(2, m, strlen(m));
        return 1;
    }

    char line[96];
    int n = snprintf(line, sizeof(line),
                     "mt-echo: listening port=%d threads=%d\n",
                     g_port, g_threads);
    if (n > 0) {
        (void)write(1, line, (size_t)n);
    }
    /* Also via stdio+flush in case the harness reads buffered stdout. */
    fprintf(stdout, "mt-echo: ready\n");
    fflush(stdout);

    /* Run forever; workers never return. */
    for (long i = 0; i < g_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    free(tids);
    return 0;
}
