/* loadgen — multithreaded TCP load generator for mt_echo_server.
 *
 * Opens C persistent connections spread across T client threads, each
 * connection loops request -> response as fast as it can for D
 * seconds, and aggregates:
 *   - total completed requests -> req/s throughput
 *   - a latency histogram -> p50 / p99 / p99.9 (microseconds)
 *
 * This is the host-side benchmark driver. It is a plain dynamic build
 * (runs on the host, NOT inside NARF), so it links against the host
 * libc and uses host pthreads. It mirrors what redis-bench does for
 * redis: drive a real off-box TCP workload and report throughput +
 * tail latency.
 *
 * USAGE
 *   loadgen <host> <port> <connections> <duration_sec> [threads] [reqbytes]
 *     host        target IP (e.g. 127.0.0.1 or 10.0.2.15 over tap)
 *     port        target port
 *     connections total concurrent persistent connections
 *     duration    seconds to run the measured phase
 *     threads     client threads (default: min(connections, 16))
 *     reqbytes    request payload size in bytes (default 16)
 *
 * The server replies with a small fixed message; we just read until we
 * get >=1 byte back (one round trip = one request).
 *
 * BUILD: gcc -O2 -pthread -o loadgen loadgen.c   (see build.sh)
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Latency histogram: log-linear buckets over 1us .. ~1s.
 * Bucket i covers [i*BUCKET_US, (i+1)*BUCKET_US) microseconds, with a
 * coarse overflow tail. Resolution 1us up to HIST_FINE us, then
 * everything above goes to the last bucket. 1,000,000 fine buckets is
 * a few MB — fine for a benchmark and gives exact percentiles up to
 * 1s. */
#define HIST_FINE 1000000 /* 1us .. 1,000,000us = 1s, 1us resolution */
#define HIST_BUCKETS (HIST_FINE + 1)

typedef struct {
    int thread_idx;
    const char *host;
    int port;
    int nconns;     /* connections owned by this thread */
    int reqbytes;
    volatile int *go;      /* spin until set: start measured phase together */
    volatile int *stop;    /* set when duration elapsed */
    uint64_t count;        /* requests completed (measured phase) */
    uint64_t errors;
    uint32_t *hist;        /* per-thread histogram, HIST_BUCKETS */
} worker_t;

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int connect_one(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* One blocking request/response round trip. Returns 0 on success and
 * records latency in *lat_ns. <0 on connection error. */
static int do_request(int fd, const char *req, int reqlen, uint64_t *lat_ns) {
    uint64_t t0 = now_ns();
    int off = 0;
    while (off < reqlen) {
        ssize_t w = write(fd, req + off, (size_t)(reqlen - off));
        if (w > 0) off += (int)w;
        else if (w < 0 && errno == EINTR) continue;
        else return -1;
    }
    char buf[512];
    ssize_t r;
    do {
        r = read(fd, buf, sizeof(buf));
    } while (r < 0 && errno == EINTR);
    if (r <= 0) return -1;
    *lat_ns = now_ns() - t0;
    return 0;
}

static void hist_record(uint32_t *hist, uint64_t lat_ns) {
    uint64_t us = lat_ns / 1000;
    if (us >= HIST_FINE) us = HIST_FINE; /* overflow tail */
    hist[us]++;
}

static void *worker_fn(void *arg) {
    worker_t *w = (worker_t *)arg;
    int *fds = calloc((size_t)w->nconns, sizeof(int));
    if (!fds) { w->errors += (uint64_t)w->nconns; return NULL; }

    /* Establish all connections for this thread. */
    int live = 0;
    for (int i = 0; i < w->nconns; i++) {
        int fd = connect_one(w->host, w->port);
        if (fd >= 0) fds[i] = fd, live++;
        else fds[i] = -1, w->errors++;
    }

    char *req = malloc((size_t)w->reqbytes);
    memset(req, 'x', (size_t)w->reqbytes);
    if (w->reqbytes > 0) req[w->reqbytes - 1] = '\n';

    /* Wait for the synchronized start. */
    while (!*(w->go)) { /* spin */ }

    /* Round-robin across this thread's connections so all are kept
     * busy; closed/broken connections are reconnected lazily. */
    while (!*(w->stop)) {
        for (int i = 0; i < w->nconns; i++) {
            if (*(w->stop)) break;
            if (fds[i] < 0) {
                fds[i] = connect_one(w->host, w->port);
                if (fds[i] < 0) { w->errors++; continue; }
            }
            uint64_t lat;
            if (do_request(fds[i], req, w->reqbytes, &lat) == 0) {
                w->count++;
                hist_record(w->hist, lat);
            } else {
                close(fds[i]);
                fds[i] = -1;
                w->errors++;
            }
        }
    }

    for (int i = 0; i < w->nconns; i++)
        if (fds[i] >= 0) close(fds[i]);
    free(fds);
    free(req);
    (void)live;
    return NULL;
}

/* Compute percentile (0..1) from a merged histogram of `total`
 * samples. Returns microseconds. */
static uint64_t percentile(const uint64_t *merged, uint64_t total, double p) {
    if (total == 0) return 0;
    uint64_t target = (uint64_t)(p * (double)total);
    if (target >= total) target = total - 1;
    uint64_t acc = 0;
    for (uint64_t i = 0; i < HIST_BUCKETS; i++) {
        acc += merged[i];
        if (acc > target) return i; /* bucket i == i microseconds */
    }
    return HIST_FINE;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <host> <port> <connections> <duration_sec> "
                "[threads] [reqbytes]\n",
                argv[0]);
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    int conns = atoi(argv[3]);
    int dur = atoi(argv[4]);
    int threads = (argc > 5) ? atoi(argv[5]) : 0;
    int reqbytes = (argc > 6) ? atoi(argv[6]) : 16;
    if (conns <= 0) conns = 1;
    if (dur <= 0) dur = 5;
    if (reqbytes <= 0) reqbytes = 16;
    if (threads <= 0) threads = conns < 16 ? conns : 16;
    if (threads > conns) threads = conns;

    worker_t *ws = calloc((size_t)threads, sizeof(worker_t));
    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    volatile int go = 0, stop = 0;

    /* Distribute connections across threads as evenly as possible. */
    int base = conns / threads, extra = conns % threads;
    for (int t = 0; t < threads; t++) {
        ws[t].thread_idx = t;
        ws[t].host = host;
        ws[t].port = port;
        ws[t].nconns = base + (t < extra ? 1 : 0);
        ws[t].reqbytes = reqbytes;
        ws[t].go = &go;
        ws[t].stop = &stop;
        ws[t].hist = calloc(HIST_BUCKETS, sizeof(uint32_t));
        if (!ws[t].hist) { fprintf(stderr, "loadgen: OOM hist\n"); return 1; }
    }

    fprintf(stderr,
            "loadgen: target=%s:%d conns=%d threads=%d dur=%ds reqbytes=%d\n",
            host, port, conns, threads, dur, reqbytes);

    for (int t = 0; t < threads; t++)
        pthread_create(&tids[t], NULL, worker_fn, &ws[t]);

    /* Give connections a moment to establish, then start measuring. */
    struct timespec warmup = {0, 200 * 1000 * 1000};
    nanosleep(&warmup, NULL);

    uint64_t start = now_ns();
    go = 1;
    struct timespec run = {dur, 0};
    nanosleep(&run, NULL);
    stop = 1;
    uint64_t elapsed_ns = now_ns() - start;

    for (int t = 0; t < threads; t++)
        pthread_join(tids[t], NULL);

    /* Merge results. */
    uint64_t total = 0, errors = 0;
    uint64_t *merged = calloc(HIST_BUCKETS, sizeof(uint64_t));
    for (int t = 0; t < threads; t++) {
        total += ws[t].count;
        errors += ws[t].errors;
        for (uint64_t i = 0; i < HIST_BUCKETS; i++)
            merged[i] += ws[t].hist[i];
        free(ws[t].hist);
    }

    double secs = (double)elapsed_ns / 1e9;
    double rps = secs > 0 ? (double)total / secs : 0;
    uint64_t p50 = percentile(merged, total, 0.50);
    uint64_t p99 = percentile(merged, total, 0.99);
    uint64_t p999 = percentile(merged, total, 0.999);

    /* Human-readable line. */
    fprintf(stdout,
            "RESULT host=%s port=%d conns=%d threads=%d secs=%.3f "
            "requests=%llu errors=%llu rps=%.0f "
            "p50_us=%llu p99_us=%llu p999_us=%llu\n",
            host, port, conns, threads, secs,
            (unsigned long long)total, (unsigned long long)errors, rps,
            (unsigned long long)p50, (unsigned long long)p99,
            (unsigned long long)p999);
    /* Machine-parseable key=val also goes to stdout above; nothing
     * else is printed on stdout so a harness can scrape it. */

    free(merged);
    free(ws);
    free(tids);
    return 0;
}
