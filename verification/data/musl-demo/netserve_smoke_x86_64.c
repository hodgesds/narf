// Off-box network-stack smoke. The guest half of the live TCP/UDP/DNS test:
//
//   1. bind 0.0.0.0:7777, accept one host-forwarded TCP connection, echo it;
//   2. bind 0.0.0.0:7779, accept a host-forwarded bulk stream, verify every
//      byte of a known pattern and echo it all back (the host verifies the
//      echo) — GRO merging, receive windows and ACK pacing both ways;
//   3. as a CLIENT, non-blocking connect() to the host (10.0.2.2:17780) and
//      download a large patterned stream to EOF through poll() — the browser
//      shape (Firefox/Chromium sockets are non-blocking + poll/epoll);
//      then 8 and 16 concurrent downloads from 10.0.2.2:17782, read through
//      one epoll loop and through one blocking thread per socket;
//   4. bind 0.0.0.0:7778 and echo host datagrams of many sizes, including
//      ones above the MTU that arrive and leave as IPv4 fragments, then a
//      back-to-back burst;
//   5. as a CLIENT, a connect()ed UDP socket round-trips datagrams with the
//      host (10.0.2.2:17781) via send()/recv() — the QUIC socket shape —
//      then sends UDP_GSO_SEGS datagrams in ONE sendmsg with a UDP_SEGMENT
//      cmsg (UDP GSO, as ngtcp2 / Chromium / Firefox QUIC batch their
//      packets) under IP_PMTUDISC_DO and reads each one's echo back with
//      UDP_GRO enabled;
//   6. send a DNS A query to QEMU SLIRP's resolver at 10.0.2.3 and validate
//      the reply header.
//
// These exercise the full socket -> route/ARP -> virtio-net paths against
// genuine off-box peers, not loopback or synthetic packet injection.
//
// Tokens on the serial console:
//   * "netserve: listening" — emitted after TCP listen(), BEFORE accept().
//     The host-side harness waits for this before opening its socket.
//   * "netserve-tcp-ok"     — after the TCP echo round-trip.
//   * "netserve: bulk listening" / "netserve-bulk-ok" — bulk echo (2).
//   * "netserve-download-ok" — client download (3).
//   * "netserve-parallel-ok" — 8 and 16 concurrent downloads, read through
//     epoll and through per-socket threads, then a fresh connection (3b).
//   * "netserve: udp listening" / "netserve-udp-ok" — UDP echo (4).
//   * "netserve-udp-client-ok" — connected UDP client (5).
//   * "netserve-udp-gso-ok" — UDP GSO send + UDP_GRO receive (5).
// Sizes and the pattern MUST match `net_smoke_cmd_with_nic` in xtask.
//   * "netserve-dns-ok"     — after a valid DNS response.
//   * "netserve-ok"         — all three paths passed.
//
// Build: the uniform musl-demo recipe (musl-gcc -O2 -fPIE -pie).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <pthread.h>

// `include/uapi/linux/udp.h`; musl's <netinet/udp.h> may predate them.
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

// The host as the guest reaches it. SLIRP's alias by default; a host-Linux
// run of these phases against a local server overrides it.
#ifndef NETSERVE_HOST
#define NETSERVE_HOST "10.0.2.2"
#endif

#define BULK_LEN (4u << 20)
#define BULK_SEED 0x5a
#define DOWNLOAD_LEN (8u << 20)
#define DOWNLOAD_SEED 0xc3
#define UDP_BURST 64
#define UDP_BURST_LEN 1200
#define UDP_CLIENT_ROUNDS 16
#define UDP_CLIENT_LEN 1200
#define UDP_GSO_SEGS 5
#define UDP_GSO_LEN 1200
#define UDP_GSO_SEED 0x90
// The parallel-download phase: PAR_LEN bytes per stream from the host's
// PAR_PORT. The guest names each stream's seed in the one byte it sends first.
#define PAR_PORT 17782
#define PAR_LEN (16u << 20)
#define PAR_MAX 16

static void w(const char *m) { write(1, m, strlen(m)); }

static int failf(const char *what, unsigned long a, unsigned long b) {
    char buf[320];
    snprintf(buf, sizeof buf, "netserve-fail: %s (%lu, %lu, errno %d)\n", what, a, b, errno);
    w(buf);
    return 1;
}

// The stream pattern: byte i of a stream seeded `seed`. A multiplicative hash
// so a dropped, duplicated or reordered segment shows up at its offset.
static uint8_t pat(uint64_t i, uint8_t seed) {
    return (uint8_t)((i * 2654435761u) >> 13) ^ (uint8_t)(i >> 20) ^ seed;
}

static long first_mismatch(const uint8_t *p, size_t n, uint64_t off, uint8_t seed) {
    for (size_t k = 0; k < n; k++)
        if (p[k] != pat(off + k, seed)) return (long)k;
    return -1;
}

static int write_all(int fd, const uint8_t *p, size_t n) {
    while (n) {
        long m = write(fd, p, n);
        if (m <= 0) return -1;
        p += m;
        n -= (size_t)m;
    }
    return 0;
}

static int listen_on(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 4) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static void host_addr(struct sockaddr_in *a, int port) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    inet_pton(AF_INET, NETSERVE_HOST, &a->sin_addr); // SLIRP's alias for the host
}

// (2) Verify a BULK_LEN patterned stream and echo every byte back.
static int bulk_echo(void) {
    int s = listen_on(7779);
    if (s < 0) return failf("bulk listen", 0, 0);
    w("netserve: bulk listening on 0.0.0.0:7779\n");
    int c = accept(s, 0, 0);
    if (c < 0) return failf("bulk accept", 0, 0);
    static uint8_t buf[65536];
    uint64_t got = 0;
    for (;;) {
        long n = read(c, buf, sizeof buf);
        if (n < 0) return failf("bulk read", got, 0);
        if (n == 0) break;
        long bad = first_mismatch(buf, (size_t)n, got, BULK_SEED);
        if (bad >= 0) return failf("bulk byte mismatch at offset", got + (uint64_t)bad, buf[bad]);
        if (write_all(c, buf, (size_t)n) < 0) return failf("bulk echo write", got, 0);
        got += (uint64_t)n;
    }
    if (got != BULK_LEN) return failf("bulk length", got, BULK_LEN);
    // Half-close so the host's read sees EOF after the full echo.
    if (shutdown(c, SHUT_WR) < 0) return failf("bulk shutdown", 0, 0);
    // Drain until the host closes, so our close() cannot RST unread data.
    while (read(c, buf, sizeof buf) > 0) {
    }
    close(c);
    close(s);
    w("netserve-bulk-ok\n");
    return 0;
}

// (3) Non-blocking client download to EOF, driven by poll().
static int download(void) {
    int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (c < 0) return failf("download socket", 0, 0);
    struct sockaddr_in a;
    host_addr(&a, 17780);
    if (connect(c, (struct sockaddr *)&a, sizeof a) == 0) {
        // Linux may complete a loopback-fast connect at once; fine.
    } else if (errno != EINPROGRESS) {
        return failf("download connect", 0, 0);
    }
    struct pollfd p = {.fd = c, .events = POLLOUT};
    if (poll(&p, 1, 20000) != 1 || !(p.revents & POLLOUT))
        return failf("download connect poll", p.revents, 0);
    int err = -1;
    socklen_t el = sizeof err;
    if (getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0)
        return failf("download SO_ERROR", (unsigned long)err, 0);
    static uint8_t buf[65536];
    uint64_t got = 0;
    for (;;) {
        long n = read(c, buf, sizeof buf);
        if (n > 0) {
            long bad = first_mismatch(buf, (size_t)n, got, DOWNLOAD_SEED);
            if (bad >= 0)
                return failf("download byte mismatch at offset", got + (uint64_t)bad, buf[bad]);
            got += (uint64_t)n;
            continue;
        }
        if (n == 0) break;
        if (errno != EAGAIN) return failf("download read", got, 0);
        p.events = POLLIN;
        p.revents = 0;
        // A parked reader must be woken by arriving data: a lost wake hangs here.
        if (poll(&p, 1, 20000) != 1) return failf("download stalled (poll timeout) at", got, 0);
    }
    close(c);
    if (got != DOWNLOAD_LEN) return failf("download length", got, DOWNLOAD_LEN);
    w("netserve-download-ok\n");
    return 0;
}

// (3b) Many concurrent downloads, the browser shape (a page or a video player
// opens many connections at once and reads all of them as data arrives). Each
// stream is a PAR_LEN patterned stream whose seed the guest picks; every byte
// and the EOF are verified. Run with one epoll loop over non-blocking sockets
// and with one blocking reader thread per socket. Every stream must make
// progress: the slowest one may not finish far behind the first.
struct par_stream {
    int fd;
    uint8_t seed;
    uint64_t got;
    long done_ms; // completion time since the round began, -1 while open
    const char *err;
};

static struct timespec par_t0;

static long par_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - par_t0.tv_sec) * 1000L + (t.tv_nsec - par_t0.tv_nsec) / 1000000L;
}

// Blocking connect to the parallel server, then send the seed byte.
static int par_connect(uint8_t seed, int nonblock) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) return -1;
    struct sockaddr_in a;
    host_addr(&a, PAR_PORT);
    if (connect(c, (struct sockaddr *)&a, sizeof a) < 0 || write(c, &seed, 1) != 1) {
        close(c);
        return -1;
    }
    if (nonblock) fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
    return c;
}

// Verify and account `buf[0..n]` for stream `st`; 0 = ok.
static int par_take(struct par_stream *st, const uint8_t *buf, long n) {
    if (st->got + (uint64_t)n > PAR_LEN) {
        st->err = "overlong stream";
        return -1;
    }
    if (first_mismatch(buf, (size_t)n, st->got, st->seed) >= 0) {
        st->err = "byte mismatch";
        return -1;
    }
    st->got += (uint64_t)n;
    return 0;
}

static void *par_reader(void *arg) {
    struct par_stream *st = arg;
    static __thread uint8_t buf[65536];
    struct timeval t = {.tv_sec = 20};
    setsockopt(st->fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
    for (;;) {
        long n = read(st->fd, buf, sizeof buf);
        if (n < 0) {
            st->err = errno == EAGAIN ? "stalled (20 s without data)" : "read error";
            return 0;
        }
        if (n == 0) break;
        if (par_take(st, buf, n)) return 0;
    }
    st->done_ms = par_ms();
    return 0;
}

static int par_epoll(struct par_stream *st, int n) {
    int ep = epoll_create1(0);
    if (ep < 0) return failf("parallel epoll_create1", 0, 0);
    for (int i = 0; i < n; i++) {
        struct epoll_event e = {.events = EPOLLIN, .data.u32 = (uint32_t)i};
        if (epoll_ctl(ep, EPOLL_CTL_ADD, st[i].fd, &e) < 0)
            return failf("parallel epoll_ctl", (unsigned long)i, 0);
    }
    static uint8_t buf[65536];
    int open = n;
    while (open > 0) {
        struct epoll_event ev[PAR_MAX];
        int k = epoll_wait(ep, ev, PAR_MAX, 20000);
        if (k == 0) {
            for (int i = 0; i < n; i++)
                if (st[i].done_ms < 0 && !st[i].err) st[i].err = "stalled (20 s without data)";
            break;
        }
        if (k < 0) {
            if (errno == EINTR) continue;
            return failf("parallel epoll_wait", 0, 0);
        }
        for (int j = 0; j < k && open > 0; j++) {
            struct par_stream *s = &st[ev[j].data.u32];
            // One read per wake per stream, the way an event loop round-robins
            // its ready sockets; level-triggered epoll reports the rest again.
            long m = read(s->fd, buf, sizeof buf);
            if (m > 0) {
                par_take(s, buf, m);
            } else if (m == 0) {
                s->done_ms = par_ms();
            } else if (errno != EAGAIN) {
                s->err = "read error";
            }
            if (s->err) open = 0;
            else if (s->done_ms >= 0) {
                epoll_ctl(ep, EPOLL_CTL_DEL, s->fd, 0);
                open--;
            }
        }
    }
    close(ep);
    return 0;
}

// One round: `n` concurrent streams read by epoll (`threads` == 0) or by one
// blocking thread per stream. `round` keeps the seeds distinct across rounds.
static int par_round(int n, int threads, int round) {
    static struct par_stream st[PAR_MAX];
    const char *how = threads ? "threads" : "epoll";
    char m[192];
    clock_gettime(CLOCK_MONOTONIC, &par_t0);
    for (int i = 0; i < n; i++) {
        st[i] = (struct par_stream){.seed = (uint8_t)(round * PAR_MAX + i), .done_ms = -1};
        st[i].fd = par_connect(st[i].seed, !threads);
        if (st[i].fd < 0) return failf("parallel connect", (unsigned long)n, (unsigned long)i);
    }
    if (threads) {
        pthread_t th[PAR_MAX];
        for (int i = 0; i < n; i++)
            if (pthread_create(&th[i], 0, par_reader, &st[i]) != 0)
                return failf("parallel pthread_create", (unsigned long)i, 0);
        for (int i = 0; i < n; i++) pthread_join(th[i], 0);
    } else if (par_epoll(st, n)) {
        return 1;
    }
    long total = par_ms(), first = -1, last = 0;
    int bad = -1;
    for (int i = 0; i < n; i++) {
        close(st[i].fd);
        if (bad < 0 && (st[i].err || st[i].done_ms < 0 || st[i].got != PAR_LEN)) bad = i;
        if (st[i].done_ms >= 0 && (first < 0 || st[i].done_ms < first)) first = st[i].done_ms;
        if (st[i].done_ms > last) last = st[i].done_ms;
    }
    // Every stream's completion time (or KiB received if it never finished),
    // so a stalled stream shows up beside the rest.
    char line[512];
    int o = snprintf(line, sizeof line, "netserve: parallel %d %s %ld ms; done ms:", n, how, total);
    for (int i = 0; i < n && o < (int)sizeof line - 16; i++) {
        if (st[i].done_ms >= 0) o += snprintf(line + o, sizeof line - o, " %ld", st[i].done_ms);
        else o += snprintf(line + o, sizeof line - o, " [%luK]", (unsigned long)(st[i].got >> 10));
    }
    if (o < (int)sizeof line - 1) line[o++] = '\n';
    write(1, line, (size_t)o);
    if (bad >= 0) {
        snprintf(m, sizeof m, "parallel %d %s stream %d %s; bytes, total", n, how, bad,
                 st[bad].err ? st[bad].err : "ended short");
        return failf(m, (unsigned long)st[bad].got, PAR_LEN);
    }
    // Fairness: the streams share one link and start together, so they end
    // together. One that ends long after the first finisher was starved.
    if (last > 2 * first + 2000) {
        snprintf(m, sizeof m, "parallel %d %s stream starved; first and last done ms", n, how);
        return failf(m, (unsigned long)first, (unsigned long)last);
    }
    return 0;
}

static int parallel_downloads(void) {
    static const int sizes[] = {8, 16};
    int round = 0;
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++)
        for (int threads = 0; threads < 2; threads++)
            if (par_round(sizes[k], threads, round++)) return 1;
    // The network must still work afterwards: one fresh connection.
    if (par_round(1, 0, round)) return 1;
    w("netserve-parallel-ok\n");
    return 0;
}

// (7) ICMP echo through a ping socket, the way `ping` sends it. Returns the
// number of replies (matching id/seq) out of `count`, spaced 100 ms apart,
// each awaited up to 1 s; reports the mean RTT in microseconds.
static int icmp_probe(const char *dst, int count, long *mean_rtt_us) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    inet_pton(AF_INET, dst, &a.sin_addr);
    int got = 0;
    long total_us = 0;
    for (int seq = 1; seq <= count; seq++) {
        uint8_t pkt[64];
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 8; // ICMP_ECHO; the kernel fills id and checksum
        pkt[6] = (uint8_t)(seq >> 8);
        pkt[7] = (uint8_t)seq;
        for (int k = 8; k < (int)sizeof pkt; k++) pkt[k] = (uint8_t)(k ^ seq);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (sendto(s, pkt, sizeof pkt, 0, (struct sockaddr *)&a, sizeof a) != (long)sizeof pkt) break;
        for (;;) {
            struct pollfd p = {.fd = s, .events = POLLIN};
            if (poll(&p, 1, 1000) != 1) break;
            uint8_t r[256];
            long n = recv(s, r, sizeof r, 0);
            if (n >= 8 && r[0] == 0 && ((r[6] << 8) | r[7]) == seq) {
                clock_gettime(CLOCK_MONOTONIC, &t1);
                total_us += (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000;
                got++;
                break;
            }
        }
        struct timespec gap = {0, 100 * 1000 * 1000};
        nanosleep(&gap, NULL);
    }
    close(s);
    *mean_rtt_us = got ? total_us / got : -1;
    return got;
}

static int icmp_checks(void) {
    char m[128];
    long rtt;
    int gw = icmp_probe("10.0.2.2", 20, &rtt);
    snprintf(m, sizeof m, "netserve: icmp 10.0.2.2 recv=%d/20 mean_rtt_us=%ld\n", gw, rtt);
    w(m);
    if (gw != 20) return failf("icmp to the gateway lost replies", (unsigned long)gw, 20);
    int ext = icmp_probe("8.8.8.8", 20, &rtt);
    snprintf(m, sizeof m, "netserve: icmp 8.8.8.8 recv=%d/20 mean_rtt_us=%ld\n", ext, rtt);
    w(m);
    // No reply at all: the host has no external ICMP (CI); nothing to judge.
    // Otherwise the host's own path is lossless, so dropped replies are ours.
    if (ext > 0 && ext < 19) return failf("icmp to 8.8.8.8 lost replies", (unsigned long)ext, 20);
    w("netserve-icmp-ok\n");
    return 0;
}

// (5) connect()ed UDP client: send()/recv() round-trips with the host.
static int udp_client(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) return failf("udp client socket", 0, 0);
    struct timeval t = {.tv_sec = 20};
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
    struct sockaddr_in a;
    host_addr(&a, 17781);
    if (connect(u, (struct sockaddr *)&a, sizeof a) < 0) return failf("udp client connect", 0, 0);
    uint8_t out[UDP_CLIENT_LEN], in[UDP_CLIENT_LEN + 64];
    for (unsigned r = 0; r < UDP_CLIENT_ROUNDS; r++) {
        for (unsigned k = 0; k < sizeof out; k++) out[k] = pat(k, (uint8_t)(0x40 + r));
        if (send(u, out, sizeof out, 0) != (long)sizeof out) return failf("udp client send", r, 0);
        long n = recv(u, in, sizeof in, 0);
        if (n != (long)sizeof out || memcmp(in, out, sizeof out) != 0)
            return failf("udp client echo", r, (unsigned long)n);
    }
    close(u);
    w("netserve-udp-client-ok\n");
    return 0;
}

// (5b) UDP GSO: UDP_GSO_SEGS x UDP_GSO_LEN bytes leave in ONE sendmsg with a
// SOL_UDP/UDP_SEGMENT cmsg on a connected IP_PMTUDISC_DO socket, so the
// kernel must split them into separate datagrams (one 6000-byte datagram
// would be EMSGSIZE under DO). The host echoes each datagram it gets and
// checks it saw UDP_GSO_SEGS separate UDP_GSO_LEN-byte ones; here every echo
// must come back as its own segment. With UDP_GRO on, a stack that coalesces
// the echoes reports the segment size in a UDP_GRO cmsg — accept either.
static int udp_gso_client(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) return failf("udp gso socket", 0, 0);
    struct timeval t = {.tv_sec = 20};
    setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
    int pmtu = IP_PMTUDISC_DO;
    if (setsockopt(u, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof pmtu) < 0)
        return failf("udp gso IP_MTU_DISCOVER", 0, 0);
    struct sockaddr_in a;
    host_addr(&a, 17781);
    if (connect(u, (struct sockaddr *)&a, sizeof a) < 0) return failf("udp gso connect", 0, 0);
    int one = 1;
    if (setsockopt(u, SOL_UDP, UDP_GRO, &one, sizeof one) < 0)
        return failf("udp gso setsockopt UDP_GRO", 0, 0);
    int val = -1;
    socklen_t vlen = sizeof val;
    if (getsockopt(u, SOL_UDP, UDP_GRO, &val, &vlen) < 0 || val != 1)
        return failf("udp gso getsockopt UDP_GRO", (unsigned long)val, 0);
    vlen = sizeof val;
    if (getsockopt(u, SOL_UDP, UDP_SEGMENT, &val, &vlen) < 0 || val != 0)
        return failf("udp gso getsockopt UDP_SEGMENT", (unsigned long)val, 0);

    static uint8_t out[UDP_GSO_SEGS * UDP_GSO_LEN];
    for (unsigned i = 0; i < UDP_GSO_SEGS; i++)
        for (unsigned k = 0; k < UDP_GSO_LEN; k++)
            out[i * UDP_GSO_LEN + k] = pat(k, (uint8_t)(UDP_GSO_SEED + i));
    struct iovec iov = {.iov_base = out, .iov_len = sizeof out};
    union {
        char buf[CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
    } ctl;
    memset(&ctl, 0, sizeof ctl);
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl.buf;
    m.msg_controllen = sizeof ctl.buf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_UDP;
    c->cmsg_type = UDP_SEGMENT;
    c->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t gso = UDP_GSO_LEN;
    memcpy(CMSG_DATA(c), &gso, sizeof gso);
    long sent = sendmsg(u, &m, 0);
    if (sent != (long)sizeof out) return failf("udp gso sendmsg", (unsigned long)sent, 0);

    unsigned got = 0;
    while (got < UDP_GSO_SEGS) {
        static uint8_t in[65536];
        union {
            char buf[256];
            struct cmsghdr align;
        } rctl;
        struct iovec riov = {.iov_base = in, .iov_len = sizeof in};
        struct msghdr r;
        memset(&r, 0, sizeof r);
        r.msg_iov = &riov;
        r.msg_iovlen = 1;
        r.msg_control = rctl.buf;
        r.msg_controllen = sizeof rctl.buf;
        long n = recvmsg(u, &r, 0);
        if (n <= 0) return failf("udp gso recvmsg", got, 0);
        long seg = n;
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&r); h; h = CMSG_NXTHDR(&r, h))
            if (h->cmsg_level == SOL_UDP && h->cmsg_type == UDP_GRO) {
                int g;
                memcpy(&g, CMSG_DATA(h), sizeof g);
                seg = g;
            }
        for (long off = 0; off < n; off += seg) {
            long len = n - off < seg ? n - off : seg;
            if (len != UDP_GSO_LEN || got >= UDP_GSO_SEGS ||
                memcmp(in + off, out + got * UDP_GSO_LEN, UDP_GSO_LEN) != 0)
                return failf("udp gso echo", got, (unsigned long)len);
            got++;
        }
    }
    close(u);
    w("netserve-udp-gso-ok\n");
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────
// (8) TCP robustness phases: large, long-lived, paced, lossy and churned
// streams — the traffic a video player generates. Every phase dials a host
// server, reads a 64-byte config (eight little-endian u64s) that sets its
// sizes and pacing, and checks every byte against `rpat`, a cheap 64-bit PRNG
// keyed by stream offset (so a dropped, duplicated, reordered or 4-GiB-aliased
// segment shows up at its offset). Phases on 10.0.2.2 run through SLIRP; the
// `ns` phases reach a Linux TCP peer (10.0.3.1) in an unprivileged network
// namespace over the second NIC, where netem adds delay, loss, reordering and
// duplication. Ports and the config layout MUST match xtask's net_robust.rs.
// ─────────────────────────────────────────────────────────────────────────
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <net/if.h>
// musl ships no <linux/*> headers: the RTM_NEWADDR wire structs
// (include/uapi/linux/{netlink,rtnetlink,if_addr}.h).
struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type, nlmsg_flags;
    uint32_t nlmsg_seq, nlmsg_pid;
};
struct nlmsgerr {
    int error;
    struct nlmsghdr msg;
};
struct sockaddr_nl {
    sa_family_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid, nl_groups;
};
struct ifaddrmsg {
    uint8_t ifa_family, ifa_prefixlen, ifa_flags, ifa_scope;
    uint32_t ifa_index;
};
struct rtattr {
    unsigned short rta_len, rta_type;
};
#define NETLINK_ROUTE 0
#define NLMSG_ERROR 2
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define RTM_NEWADDR 20
#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define RTA_LENGTH(n) (sizeof(struct rtattr) + (n))
#define NLMSG_DATA(h) ((void *)((char *)(h) + sizeof(struct nlmsghdr)))
#include <signal.h>

#define R_CTRL_PORT 17799
#define R_WRAP_PORT 17790
#define R_ZRX_PORT 17791
#define R_ZTX_PORT 17792
#define R_BIGIO_PORT 17793
#define R_CHURN_CTL_PORT 17794
#define R_CHURN_GUEST_PORT 7795
#define R_CHURN_PORT 17796
#define R_MISC_PORT 17797
#define NS_HOST "10.0.3.1"
#define NS_GUEST_ADDR 0x0a00030f // 10.0.3.15
#define NS_BDP_PORT 17810
#define NS_LOSS_PORT 17811
#define NS_BLACKOUT_PORT 17812
#define NS_KEEPALIVE_PORT 17813
#define NS_RST_PORT 17814
#define NS_ZWIN_PORT 17815
#define NS_WRAP_PORT 17816
#define NS_CTRL_PORT 17819

static long r_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void r_sleep_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) < 0 && errno == EINTR) {
    }
}

// Word `k` of the stream seeded `s`: splitmix64. Byte `off` of the stream is
// byte (off & 7) of word (off >> 3).
static inline uint64_t rword(uint64_t k, uint64_t s) {
    uint64_t z = k * 0x9E3779B97F4A7C15ull + s * 0xD1B54A32D192ED03ull + 1;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static void rfill(uint8_t *p, size_t n, uint64_t off, uint64_t s) {
    while (n && (off & 7)) {
        *p++ = (uint8_t)(rword(off >> 3, s) >> ((off & 7) * 8));
        off++;
        n--;
    }
    while (n >= 8) {
        uint64_t v = rword(off >> 3, s);
        memcpy(p, &v, 8);
        p += 8;
        off += 8;
        n -= 8;
    }
    while (n) {
        *p++ = (uint8_t)(rword(off >> 3, s) >> ((off & 7) * 8));
        off++;
        n--;
    }
}

// Offset of the first byte of p[0..n] that differs from the stream, or -1.
static long rcheck(const uint8_t *p, size_t n, uint64_t off, uint64_t s) {
    size_t i = 0;
    while (i < n && ((off + i) & 7)) {
        if (p[i] != (uint8_t)(rword((off + i) >> 3, s) >> (((off + i) & 7) * 8))) return (long)i;
        i++;
    }
    while (i + 8 <= n) {
        uint64_t v = rword((off + i) >> 3, s), got;
        memcpy(&got, p + i, 8);
        if (got != v) {
            for (size_t k = 0; k < 8; k++)
                if (p[i + k] != (uint8_t)(v >> (k * 8))) return (long)(i + k);
        }
        i += 8;
    }
    while (i < n) {
        if (p[i] != (uint8_t)(rword((off + i) >> 3, s) >> (((off + i) & 7) * 8))) return (long)i;
        i++;
    }
    return -1;
}

struct rcfg {
    uint64_t v[8];
};

static int r_dial(const char *host, int port) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    for (int tries = 0; tries < 50; tries++) {
        if (connect(c, (struct sockaddr *)&a, sizeof a) == 0) return c;
        if (errno != ECONNREFUSED && errno != ETIMEDOUT) break;
        // A server between rounds (or still binding) refuses; retry.
        close(c);
        c = socket(AF_INET, SOCK_STREAM, 0);
        if (c < 0) return -1;
        r_sleep_ms(200);
    }
    close(c);
    return -1;
}

static int r_read_full(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n) {
        long m = read(fd, p, n);
        if (m <= 0) return -1;
        p += m;
        n -= (size_t)m;
    }
    return 0;
}

static int r_cfg(int fd, struct rcfg *c) {
    uint8_t b[64];
    // The config arrives at once; never hang on it.
    struct timeval t = {.tv_sec = 30}, none = {0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
    int rc = r_read_full(fd, b, sizeof b);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none);
    if (rc) return -1;
    for (int i = 0; i < 8; i++) {
        uint64_t v = 0;
        for (int k = 7; k >= 0; k--) v = (v << 8) | b[i * 8 + k];
        c->v[i] = v;
    }
    return 0;
}

static int r_tcp_info(int fd, struct tcp_info *ti) {
    socklen_t l = sizeof *ti;
    memset(ti, 0, sizeof *ti);
    return getsockopt(fd, IPPROTO_TCP, TCP_INFO, ti, &l);
}

static int r_inq(int fd) {
    int v = -1;
    if (ioctl(fd, TIOCINQ, &v) < 0) return -1;
    return v;
}

static int r_outq(int fd) {
    int v = -1;
    if (ioctl(fd, TIOCOUTQ, &v) < 0) return -1;
    return v;
}

// Bytes written so far by the current r_send_stream on this thread.
static __thread volatile uint64_t *r_send_progress;

// Write `len` bytes of stream `seed` starting at stream offset 0.
static int r_send_stream(int fd, uint64_t len, uint64_t seed, size_t chunk) {
    static __thread uint8_t *buf;
    if (!buf) buf = malloc(1u << 20);
    if (!buf) return -1;
    if (chunk > (1u << 20)) chunk = 1u << 20;
    uint64_t off = 0;
    while (off < len) {
        size_t n = (size_t)(len - off < chunk ? len - off : chunk);
        rfill(buf, n, off, seed);
        if (write_all(fd, buf, n)) return -1;
        off += n;
        if (r_send_progress) *r_send_progress = off;
    }
    return 0;
}

// On a stall or failure: the kernel's view of every TCP connection.
static void r_dump_tcp(void) {
    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) return;
    static char b[16384];
    long n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n > 0) {
        w("netserve: /proc/net/tcp at failure:\n");
        write(1, b, (size_t)n);
    }
}

// Read and verify exactly `len` bytes of stream `seed`, then require EOF if
// `want_eof`. Returns 0, or -1 with `*at` = the stream offset of the failure.
static int r_recv_stream(int fd, uint64_t len, uint64_t seed, int want_eof, uint64_t *at,
                         const char **why) {
    static __thread uint8_t *buf;
    if (!buf) buf = malloc(1u << 20);
    if (!buf) return -1;
    uint64_t got = 0;
    while (got < len) {
        size_t want = (size_t)(len - got < (1u << 20) ? len - got : (1u << 20));
        long n = read(fd, buf, want);
        if (n <= 0) {
            *at = got;
            *why = n == 0 ? "early EOF" : "read error";
            return -1;
        }
        long bad = rcheck(buf, (size_t)n, got, seed);
        if (bad >= 0) {
            *at = got + (uint64_t)bad;
            *why = "byte mismatch";
            return -1;
        }
        got += (uint64_t)n;
    }
    if (want_eof) {
        long n = read(fd, buf, 1);
        if (n != 0) {
            *at = got;
            *why = n > 0 ? "data past the end" : "no EOF (read error)";
            return -1;
        }
    }
    *at = got;
    return 0;
}

struct r_tx_job {
    int fd;
    uint64_t len, seed;
    int shut;
    int rc;
    volatile uint64_t sent;
};

static void *r_tx_thread(void *arg) {
    struct r_tx_job *j = arg;
    r_send_progress = &j->sent;
    j->rc = r_send_stream(j->fd, j->len, j->seed, 256 << 10);
    if (j->rc == 0 && j->shut) j->rc = shutdown(j->fd, SHUT_WR);
    return 0;
}

// Full duplex: `down` bytes in (seed s) while `up` bytes go out (seed s+1),
// both directions at once; our side is half-closed at its end, and the peer
// answers with a one-byte verdict ('K') once it has checked every byte we
// sent. Reports MB/s.
static int r_duplex(int c, uint64_t down, uint64_t up, uint64_t s, const char *what) {
    struct r_tx_job tx = {.fd = c, .len = up, .seed = s + 1, .shut = 1};
    pthread_t th;
    // A stall surfaces as a timeout with the progress of both directions,
    // never as a hang.
    struct timeval tmo = {.tv_sec = 60};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof tmo);
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tmo, sizeof tmo);
    long t0 = r_ms();
    if (pthread_create(&th, 0, r_tx_thread, &tx) != 0) return failf(what, 0, 0);
    uint64_t at = 0;
    const char *why = 0;
    // No EOF check here: the peer's one-byte verdict follows the stream.
    int rrc = r_recv_stream(c, down, s, 0, &at, &why);
    pthread_join(th, 0);
    long ms = r_ms() - t0;
    struct tcp_info ti;
    r_tcp_info(c, &ti);
    char m[320];
    snprintf(m, sizeof m,
             "netserve: %s down=%llu up=%llu in %ld ms (%llu MB/s) retrans=%u snd_mss=%u "
             "rcv_mss=%u wscale=%u/%u rtt_us=%u\n",
             what, (unsigned long long)down, (unsigned long long)up, ms,
             (unsigned long long)((down + up) / 1000 / (ms ? ms : 1)), ti.tcpi_total_retrans,
             ti.tcpi_snd_mss, ti.tcpi_rcv_mss, ti.tcpi_snd_wscale, ti.tcpi_rcv_wscale,
             ti.tcpi_rtt);
    w(m);
    if (rrc || tx.rc) r_dump_tcp();
    if (rrc) {
        snprintf(m, sizeof m, "%s download %s at offset (upload at %llu); offset, length", what, why,
                 (unsigned long long)tx.sent);
        return failf(m, (unsigned long)at, (unsigned long)down);
    }
    if (tx.rc) return failf("upload failed; sent, length", (unsigned long)tx.sent, (unsigned long)up);
    return 0;
}

// (8a) Sequence-space wrap: one connection, `v0` bytes down and `v1` up at
// once (> 4 GiB each in the long run, so both directions wrap).
static int r_wrap(void) {
    int c = r_dial(NETSERVE_HOST, R_WRAP_PORT);
    if (c < 0) return failf("wrap connect", 0, 0);
    struct rcfg cfg;
    if (r_cfg(c, &cfg)) return failf("wrap config", 0, 0);
    if (r_duplex(c, cfg.v[0], cfg.v[1], cfg.v[2], "wrap")) return 1;
    // The host confirms it verified every upstream byte.
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("wrap host verdict", 0, 0);
    close(c);
    w("netserve-wrap-ok\n");
    return 0;
}

// (8b) Zero window, receive side: the host streams `v0` bytes; we read `v1`
// bytes, then stop reading for a pause (every fourth pause `v4` ms, the
// others `v2` ms) — the video player shape. During each pause the receive
// queue must fill and stop growing (the window is closed), and after it the
// stream must resume within `v5` ms (the window update reopens it).
static int r_zwin_rx(void) {
    int c = r_dial(NETSERVE_HOST, R_ZRX_PORT);
    if (c < 0) return failf("zwin-rx connect", 0, 0);
    struct rcfg cfg;
    if (r_cfg(c, &cfg)) return failf("zwin-rx config", 0, 0);
    uint64_t total = cfg.v[0], burst = cfg.v[1], seed = cfg.v[3];
    static uint8_t buf[65536];
    uint64_t got = 0;
    int pauses = 0;
    long worst_resume = 0;
    int min_full = 1 << 30;
    char m[256];
    while (got < total) {
        uint64_t stop = got + burst < total ? got + burst : total;
        while (got < stop) {
            size_t want = (size_t)(stop - got < sizeof buf ? stop - got : sizeof buf);
            long n = read(c, buf, want);
            if (n <= 0) return failf("zwin-rx read", (unsigned long)got, (unsigned long)n);
            long bad = rcheck(buf, (size_t)n, got, seed);
            if (bad >= 0) return failf("zwin-rx byte mismatch at", got + (uint64_t)bad, 0);
            got += (uint64_t)n;
        }
        if (got >= total) break;
        long pause = (pauses % 4 == 3) ? (long)cfg.v[4] : (long)cfg.v[2];
        r_sleep_ms(pause);
        // The queue is full and the window closed: two samples agree.
        int q1 = r_inq(c);
        r_sleep_ms(300);
        int q2 = r_inq(c);
        if (q1 <= 0 || q1 != q2) {
            snprintf(m, sizeof m, "zwin-rx pause %d: receive queue not full and stable; SIOCINQ",
                     pauses);
            return failf(m, (unsigned long)q1, (unsigned long)q2);
        }
        if (q2 < min_full) min_full = q2;
        // Resume: drain what was queued, then time the first fresh byte.
        uint64_t queued_end = got + (uint64_t)q2;
        long t0 = r_ms(), first_new = -1;
        while (got < total && (first_new < 0 || got < queued_end)) {
            long n = read(c, buf, sizeof buf);
            if (n <= 0) return failf("zwin-rx resume read", (unsigned long)got, 0);
            long bad = rcheck(buf, (size_t)n, got, seed);
            if (bad >= 0) return failf("zwin-rx byte mismatch at", got + (uint64_t)bad, 0);
            got += (uint64_t)n;
            if (got > queued_end && first_new < 0) first_new = r_ms() - t0;
        }
        if (first_new > worst_resume) worst_resume = first_new;
        if (first_new > (long)cfg.v[5]) {
            snprintf(m, sizeof m, "zwin-rx pause %d: stream resumed late; ms, limit", pauses);
            return failf(m, (unsigned long)first_new, (unsigned long)cfg.v[5]);
        }
        pauses++;
    }
    long n = read(c, buf, 1);
    if (n != 0) return failf("zwin-rx no EOF", (unsigned long)n, 0);
    close(c);
    snprintf(m, sizeof m,
             "netserve: zwin-rx %llu bytes, %d pauses, full queue >= %d bytes, worst resume %ld ms\n",
             (unsigned long long)total, pauses, min_full, worst_resume);
    w(m);
    w("netserve-zwin-rx-ok\n");
    return 0;
}

// (8c) Zero window, send side: we send `v0` bytes non-blocking while the host
// reads in bursts and pauses. While the host pauses, the send queue backs up
// (SIOCOUTQ > 0, POLLOUT clear) and our persist timer must keep probing until
// the host's window reopens; the host checks every byte and the pacing.
static int r_zwin_tx(void) {
    int c = r_dial(NETSERVE_HOST, R_ZTX_PORT);
    if (c < 0) return failf("zwin-tx connect", 0, 0);
    struct rcfg cfg;
    if (r_cfg(c, &cfg)) return failf("zwin-tx config", 0, 0);
    uint64_t total = cfg.v[0], seed = cfg.v[1];
    fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
    static uint8_t buf[65536];
    uint64_t off = 0;
    long longest = 0;
    int stalls = 0, max_outq = 0;
    while (off < total) {
        size_t n = (size_t)(total - off < sizeof buf ? total - off : sizeof buf);
        rfill(buf, n, off, seed);
        long m = write(c, buf, n);
        if (m > 0) {
            off += (uint64_t)m;
            continue;
        }
        if (m < 0 && errno != EAGAIN) return failf("zwin-tx write", (unsigned long)off, 0);
        int q = r_outq(c);
        if (q <= 0) return failf("zwin-tx EAGAIN with an empty send queue; SIOCOUTQ", (unsigned long)q, off);
        if (q > max_outq) max_outq = q;
        struct pollfd p = {.fd = c, .events = POLLOUT};
        long t0 = r_ms();
        int r = poll(&p, 1, (int)cfg.v[2]);
        long waited = r_ms() - t0;
        if (r != 1 || !(p.revents & POLLOUT))
            return failf("zwin-tx stalled waiting for POLLOUT; ms, offset", (unsigned long)waited, off);
        if (p.revents & (POLLERR | POLLHUP)) return failf("zwin-tx POLLERR/HUP", p.revents, off);
        if (waited > 500) stalls++;
        if (waited > longest) longest = waited;
    }
    fcntl(c, F_SETFL, fcntl(c, F_GETFL) & ~O_NONBLOCK);
    if (shutdown(c, SHUT_WR) < 0) return failf("zwin-tx shutdown", 0, 0);
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("zwin-tx host verdict", 0, 0);
    close(c);
    char m[200];
    snprintf(m, sizeof m,
             "netserve: zwin-tx %llu bytes, %d send stalls, longest %ld ms, max SIOCOUTQ %d\n",
             (unsigned long long)total, stalls, longest, max_outq);
    w(m);
    if (stalls == 0) return failf("zwin-tx: the host pauses never backed up the send queue", 0, 0);
    w("netserve-zwin-tx-ok\n");
    return 0;
}

static int r_mode_dial(const char *host, int port, uint8_t mode, struct rcfg *cfg) {
    int c = r_dial(host, port);
    if (c < 0) return -1;
    if (write(c, &mode, 1) != 1 || r_cfg(c, cfg)) {
        close(c);
        return -1;
    }
    return c;
}

// (8d) Large reads and writes and their socket-API semantics.
static int r_bigio(void) {
    struct rcfg cfg;
    char m[256];
    const uint64_t big = 16u << 20;
    uint8_t *buf = malloc(big);
    if (!buf) return failf("bigio malloc", 0, 0);

    // 1. One blocking 16 MiB write() must take all 16 MiB (Linux
    //    `tcp_sendmsg` waits for send-buffer space; it never returns short
    //    on a blocking socket without a signal or timeout).
    int c = r_mode_dial(NETSERVE_HOST, R_BIGIO_PORT, 1, &cfg);
    if (c < 0) return failf("bigio 1 connect", 0, 0);
    rfill(buf, big, 0, cfg.v[0]);
    long n = write(c, buf, big);
    if (n != (long)big) return failf("bigio: blocking 16 MiB write returned short", (unsigned long)n, big);
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("bigio 1 host verdict", 0, 0);
    close(c);

    // 2. MSG_WAITALL: one recv() of 16 MiB returns all 16 MiB although the
    //    host trickles it; then 3 + 5 bytes sent 200 ms apart arrive as one
    //    8-byte MSG_WAITALL read.
    c = r_mode_dial(NETSERVE_HOST, R_BIGIO_PORT, 2, &cfg);
    if (c < 0) return failf("bigio 2 connect", 0, 0);
    n = recv(c, buf, big, MSG_WAITALL);
    if (n != (long)big) return failf("bigio: MSG_WAITALL 16 MiB recv returned short", (unsigned long)n, big);
    long bad = rcheck(buf, big, 0, cfg.v[0]);
    if (bad >= 0) return failf("bigio 2 byte mismatch at", (unsigned long)bad, 0);
    n = recv(c, buf, 8, MSG_WAITALL);
    if (n != 8 || rcheck(buf, 8, big, cfg.v[0]) >= 0)
        return failf("bigio: MSG_WAITALL 8-byte recv across two segments", (unsigned long)n, 8);
    close(c);

    // 3. SIOCINQ counts queued bytes; MSG_PEEK reads without consuming.
    c = r_mode_dial(NETSERVE_HOST, R_BIGIO_PORT, 3, &cfg);
    if (c < 0) return failf("bigio 3 connect", 0, 0);
    const int inq_len = 100000;
    int q = -1;
    for (int i = 0; i < 100 && q != inq_len; i++) {
        q = r_inq(c);
        if (q != inq_len) r_sleep_ms(50);
    }
    if (q != inq_len) return failf("bigio: SIOCINQ never reported the queued bytes", (unsigned long)q, inq_len);
    n = recv(c, buf, 1000, MSG_PEEK);
    if (n != 1000 || rcheck(buf, 1000, 0, cfg.v[0]) >= 0) return failf("bigio: MSG_PEEK", (unsigned long)n, 1000);
    q = r_inq(c);
    if (q != inq_len) return failf("bigio: MSG_PEEK consumed data; SIOCINQ after peek", (unsigned long)q, inq_len);
    n = recv(c, buf, inq_len, MSG_WAITALL);
    if (n != inq_len || rcheck(buf, inq_len, 0, cfg.v[0]) >= 0)
        return failf("bigio: read after MSG_PEEK", (unsigned long)n, inq_len);
    q = r_inq(c);
    if (q != 0) return failf("bigio: SIOCINQ after draining", (unsigned long)q, 0);
    if (write(c, "G", 1) != 1) return failf("bigio 3 go", 0, 0);
    close(c);

    // 4. SO_SNDBUF bounds the send queue; non-blocking writes are partial
    //    then EAGAIN; SIOCOUTQ reports the unacknowledged bytes and drains
    //    to 0 once the host has read everything.
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int sb = 32768, got = 0;
    socklen_t gl = sizeof got;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &got, &gl);
    if (got != 2 * sb) return failf("bigio: SO_SNDBUF readback (Linux doubles it)", (unsigned long)got, 2 * sb);
    int rb = 65536;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    gl = sizeof got;
    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &got, &gl);
    if (got != 2 * rb) return failf("bigio: SO_RCVBUF readback", (unsigned long)got, 2 * rb);
    struct sockaddr_in a;
    host_addr(&a, R_BIGIO_PORT);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) return failf("bigio 4 connect", 0, 0);
    uint8_t mode = 4;
    if (write(s, &mode, 1) != 1 || r_cfg(s, &cfg)) return failf("bigio 4 config", 0, 0);
    gl = sizeof got;
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &got, &gl);
    if (got != 2 * sb) return failf("bigio: SO_SNDBUF changed by connect", (unsigned long)got, 2 * sb);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    const uint64_t nb_total = 4u << 20;
    rfill(buf, nb_total, 0, cfg.v[0]);
    uint64_t off = 0;
    int eagains = 0, max_outq = 0, partial = 0;
    while (off < nb_total) {
        size_t want = (size_t)(nb_total - off < (256u << 10) ? nb_total - off : (256u << 10));
        long k = write(s, buf + off, want);
        if (k > 0) {
            if ((size_t)k < want) partial++;
            off += (uint64_t)k;
            continue;
        }
        if (k == 0 || errno != EAGAIN) return failf("bigio 4 write", (unsigned long)off, (unsigned long)k);
        eagains++;
        q = r_outq(s);
        if (q > max_outq) max_outq = q;
        if (q <= 0) return failf("bigio: EAGAIN but SIOCOUTQ empty", (unsigned long)q, off);
        struct pollfd p = {.fd = s, .events = POLLOUT};
        if (poll(&p, 1, 20000) != 1) return failf("bigio 4 POLLOUT never came", off, 0);
    }
    for (int i = 0; i < 200 && (q = r_outq(s)) != 0; i++) r_sleep_ms(25);
    if (q != 0) return failf("bigio: SIOCOUTQ never drained to 0", (unsigned long)q, 0);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
    if (read(s, &ok, 1) != 1 || ok != 'K') return failf("bigio 4 host verdict", 0, 0);
    close(s);
    snprintf(m, sizeof m, "netserve: bigio nonblocking %d EAGAINs, %d partial writes, max SIOCOUTQ %d\n",
             eagains, partial, max_outq);
    w(m);
    if (eagains == 0) return failf("bigio: SO_SNDBUF 32K never filled", 0, 0);
    // Linux queues while sk_wmem_queued < sk_sndbuf: at most the doubled
    // SO_SNDBUF plus the one write that crossed it.
    if (max_outq > 2 * sb + (256 << 10)) return failf("bigio: send queue exceeded SO_SNDBUF", (unsigned long)max_outq, 2 * sb);

    // 5. TCP_INFO and TCP_MAXSEG on a connected socket.
    c = r_mode_dial(NETSERVE_HOST, R_BIGIO_PORT, 5, &cfg);
    if (c < 0) return failf("bigio 5 connect", 0, 0);
    struct tcp_info ti;
    if (r_tcp_info(c, &ti) < 0) return failf("bigio TCP_INFO", 0, 0);
    int mss = 0;
    gl = sizeof mss;
    getsockopt(c, IPPROTO_TCP, TCP_MAXSEG, &mss, &gl);
    snprintf(m, sizeof m, "netserve: bigio TCP_INFO state=%u snd_mss=%u rcv_mss=%u advmss=%u rcv_space=%u maxseg=%d\n",
             ti.tcpi_state, ti.tcpi_snd_mss, ti.tcpi_rcv_mss, ti.tcpi_advmss, ti.tcpi_rcv_space, mss);
    w(m);
    if (ti.tcpi_state != 1 || ti.tcpi_snd_mss < 536 || ti.tcpi_snd_mss > 1460)
        return failf("bigio: TCP_INFO state/snd_mss", ti.tcpi_state, ti.tcpi_snd_mss);
    if (mss < 536 || mss > 1460) return failf("bigio: TCP_MAXSEG", (unsigned long)mss, 0);
    close(c);
    free(buf);
    w("netserve-bigio-ok\n");
    return 0;
}

// /proc/net/tcp: count entries by state (st column, hex). `st[0]` totals.
static int r_tcp_states(int st[16]) {
    memset(st, 0, 16 * sizeof st[0]);
    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd < 0) return -1;
    static char b[1 << 20];
    long n = 0, k;
    while (n < (long)sizeof b - 1 && (k = read(fd, b + n, sizeof b - 1 - n)) > 0) n += k;
    close(fd);
    b[n] = 0;
    char *line = strchr(b, '\n');
    while (line && *++line) {
        unsigned s = 0;
        if (sscanf(line, "%*s %*s %*s %x", &s) == 1 && s < 16) {
            st[s]++;
            st[0]++;
        }
        line = strchr(line, '\n');
    }
    return 0;
}

static long r_meminfo_kb(const char *key) {
    int fd = open("/proc/meminfo", O_RDONLY);
    if (fd < 0) return -1;
    char b[4096];
    long n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    char *p = strstr(b, key);
    if (!p) return -1;
    return strtol(p + strlen(key) + 1, 0, 10);
}

// (8e) Connection churn: `v0` short HTTP/1.1-style fetches as a client (half
// closed by us first, so we hold TIME-WAIT; half by the host), then `v0`
// fetches into our own server from the host. Afterwards no connection may
// linger outside TIME-WAIT and the TIME-WAIT population is bounded; with
// `v1` set we wait out TIME-WAIT and require the table and memory to return
// to baseline.
static int r_churn(void) {
    int ctl = r_dial(NETSERVE_HOST, R_CHURN_CTL_PORT);
    if (ctl < 0) return failf("churn control connect", 0, 0);
    struct rcfg cfg;
    if (r_cfg(ctl, &cfg)) return failf("churn config", 0, 0);
    int count = (int)cfg.v[0];
    int base[16], st[16];
    char m[320];
    r_tcp_states(base);
    long mem0 = r_meminfo_kb("MemAvailable:");
    long t0 = r_ms();
    static uint8_t buf[65536];
    for (int i = 0; i < count; i++) {
        int c = r_dial(NETSERVE_HOST, R_CHURN_PORT);
        if (c < 0) return failf("churn connect", (unsigned long)i, 0);
        uint8_t req[64];
        memset(req, 0, sizeof req);
        memcpy(req, &i, sizeof i);
        if (write(c, req, sizeof req) != (long)sizeof req) return failf("churn request", (unsigned long)i, 0);
        uint64_t len = 100 + (uint64_t)(i % 4) * 16384;
        uint64_t at;
        const char *why;
        // Even: the host closes after the response (we see EOF). Odd: we
        // close first, the host waits for our FIN.
        if (r_recv_stream(c, len, (uint64_t)i, i % 2 == 0, &at, &why)) {
            snprintf(m, sizeof m, "churn fetch %d: %s at", i, why);
            return failf(m, (unsigned long)at, (unsigned long)len);
        }
        close(c);
    }
    long client_ms = r_ms() - t0;
    // Server side: the host connects `count` times to our :7795.
    int ls = listen_on(R_CHURN_GUEST_PORT);
    if (ls < 0) return failf("churn listen", 0, 0);
    if (write(ctl, "S", 1) != 1) return failf("churn control", 0, 0);
    t0 = r_ms();
    for (int i = 0; i < count; i++) {
        int c = accept(ls, 0, 0);
        if (c < 0) return failf("churn accept", (unsigned long)i, 0);
        uint8_t req[64];
        if (r_read_full(c, req, sizeof req)) return failf("churn server request", (unsigned long)i, 0);
        int id;
        memcpy(&id, req, sizeof id);
        uint64_t len = 100 + (uint64_t)(id % 4) * 16384;
        if (r_send_stream(c, len, (uint64_t)id + 1000000, 65536)) return failf("churn server response", (unsigned long)i, 0);
        if (id % 2 == 0) {
            // The host closes first; read its EOF.
            if (read(c, buf, 1) != 0) return failf("churn server: no EOF", (unsigned long)i, 0);
        }
        close(c);
    }
    close(ls);
    long server_ms = r_ms() - t0;
    char verdict;
    if (r_read_full(ctl, &verdict, 1) || verdict != 'K') return failf("churn host verdict", 0, 0);
    // Let the last FIN/ACK exchanges and LAST-ACK teardowns settle.
    r_sleep_ms(1000);
    r_tcp_states(st);
    long mem1 = r_meminfo_kb("MemAvailable:");
    int live = st[0] - st[6], base_live = base[0] - base[6];
    snprintf(m, sizeof m,
             "netserve: churn %d+%d fetches in %ld+%ld ms; tcp entries %d -> %d (TIME-WAIT %d -> %d); "
             "MemAvailable %ld -> %ld kB\n",
             count, count, client_ms, server_ms, base[0], st[0], base[6], st[6], mem0, mem1);
    w(m);
    // Control connection is the only new live entry.
    if (live > base_live + 1) return failf("churn: connections leaked outside TIME-WAIT", (unsigned long)live, (unsigned long)base_live + 1);
    if (st[6] > 2 * count) return failf("churn: TIME-WAIT population", (unsigned long)st[6], (unsigned long)count);
    // A TIME-WAIT socket keeps no buffers (Linux tcp_timewait_sock): the
    // whole churn may not cost more than ~2 KiB per TIME-WAIT entry.
    if (mem0 > 0 && mem1 > 0 && mem0 - mem1 > 4096 + (long)st[6] * 2)
        return failf("churn: memory grew; kB lost, TIME-WAIT entries", (unsigned long)(mem0 - mem1), (unsigned long)st[6]);
    if (cfg.v[1]) {
        // Wait out 2*MSL (60 s) and require everything back at baseline.
        long deadline = r_ms() + 75000;
        do {
            r_sleep_ms(2000);
            r_tcp_states(st);
        } while (st[6] > base[6] && r_ms() < deadline);
        long mem2 = r_meminfo_kb("MemAvailable:");
        snprintf(m, sizeof m, "netserve: churn after TIME-WAIT: tcp entries %d (TIME-WAIT %d), MemAvailable %ld kB\n",
                 st[0], st[6], mem2);
        w(m);
        if (st[6] > base[6]) return failf("churn: TIME-WAIT never expired", (unsigned long)st[6], (unsigned long)base[6]);
        if (mem0 > 0 && mem2 > 0 && mem0 - mem2 > 4096)
            return failf("churn: memory did not return to baseline (kB)", (unsigned long)(mem0 - mem2), 0);
    }
    close(ctl);
    w("netserve-churn-ok\n");
    return 0;
}

// (8f) Keepalive on an idle connection, half-close in both directions, and
// a reset from the host in the middle of a transfer.
static int r_misc(void) {
    struct rcfg cfg;
    char m[256];
    // Keepalive: probes every second while the host stays silent 6 s; SLIRP
    // answers them and the connection must still carry the host's ping.
    int c = r_mode_dial(NETSERVE_HOST, R_MISC_PORT, 1, &cfg);
    if (c < 0) return failf("keepalive connect", 0, 0);
    int one = 1, idle = 1, intvl = 1, cnt = 3;
    setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
    if (write(c, "R", 1) != 1) return failf("keepalive ready", 0, 0);
    char ping[4];
    if (r_read_full(c, ping, 4) || memcmp(ping, "ping", 4)) return failf("keepalive: idle connection died", 0, 0);
    close(c);

    // Half-close, ours: 1 MiB up, SHUT_WR, then 8 MiB down to EOF.
    c = r_mode_dial(NETSERVE_HOST, R_MISC_PORT, 2, &cfg);
    if (c < 0) return failf("half-close 2 connect", 0, 0);
    if (r_send_stream(c, 1 << 20, cfg.v[0], 65536) || shutdown(c, SHUT_WR) < 0)
        return failf("half-close 2 send", 0, 0);
    uint64_t at;
    const char *why;
    if (r_recv_stream(c, 8 << 20, cfg.v[0] + 1, 1, &at, &why)) return failf("half-close 2 download", (unsigned long)at, 0);
    close(c);

    // Half-close, the host's: it sends 1 MiB and SHUT_WR; we read to EOF,
    // then send 8 MiB into the half-open connection.
    c = r_mode_dial(NETSERVE_HOST, R_MISC_PORT, 3, &cfg);
    if (c < 0) return failf("half-close 3 connect", 0, 0);
    if (r_recv_stream(c, 1 << 20, cfg.v[0], 1, &at, &why)) return failf("half-close 3 download", (unsigned long)at, 0);
    if (r_send_stream(c, 8 << 20, cfg.v[0] + 1, 1 << 20) || shutdown(c, SHUT_WR) < 0)
        return failf("half-close 3 upload after peer FIN", 0, 0);
    char ok;
    if (read(c, &ok, 1) != 0) return failf("half-close 3: data after the host's FIN", 0, 0);
    close(c);

    // Reset from the host mid-transfer: we read some, the host aborts. The
    // read must end (ECONNRESET or EOF, whatever SLIRP forwards) rather
    // than hang, and the bytes before it must be intact.
    c = r_mode_dial(NETSERVE_HOST, R_MISC_PORT, 4, &cfg);
    if (c < 0) return failf("rst 4 connect", 0, 0);
    struct timeval tv = {.tv_sec = 20};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static uint8_t buf[65536];
    uint64_t got = 0;
    long n;
    int err = 0;
    for (;;) {
        n = read(c, buf, sizeof buf);
        if (n <= 0) {
            err = n < 0 ? errno : 0;
            break;
        }
        if (rcheck(buf, (size_t)n, got, cfg.v[0]) >= 0) return failf("rst 4 byte mismatch", got, 0);
        got += (uint64_t)n;
        if (got == (1u << 20)) {
            if (write(c, "A", 1) != 1) return failf("rst 4 abort request", 0, 0);
        }
    }
    if (err == EAGAIN) return failf("rst 4: read hung after the host's abort", got, 0);
    snprintf(m, sizeof m, "netserve: rst-from-host after %llu bytes: read %s (errno %d)\n",
             (unsigned long long)got, err ? "error" : "EOF", err);
    w(m);
    close(c);
    w("netserve-misc-ok\n");
    return 0;
}

// ── Namespace (Linux peer) phases ───────────────────────────────────────

// Give the second NIC (the one without 10.0.2.15) 10.0.3.15/24 via
// RTM_NEWADDR, as `ip addr add` does, and bring it up.
static int ns_config_iface(char *name_out) {
    struct if_nameindex *ifs = if_nameindex();
    if (!ifs) return -1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int index = 0;
    for (struct if_nameindex *i = ifs; i->if_index; i++) {
        if (!strcmp(i->if_name, "lo")) continue;
        struct ifreq r;
        memset(&r, 0, sizeof r);
        strncpy(r.ifr_name, i->if_name, IFNAMSIZ - 1);
        uint32_t addr = 0;
        if (ioctl(s, SIOCGIFADDR, &r) == 0)
            addr = ((struct sockaddr_in *)&r.ifr_addr)->sin_addr.s_addr;
        if (addr == htonl(0x0a00020f)) continue;
        if (addr == htonl(NS_GUEST_ADDR) || addr == 0) {
            index = (int)i->if_index;
            strncpy(name_out, i->if_name, IFNAMSIZ - 1);
            if (addr) {
                if_freenameindex(ifs);
                close(s);
                return 0;
            }
            break;
        }
    }
    if_freenameindex(ifs);
    if (!index) {
        close(s);
        return -1;
    }
    struct ifreq r;
    memset(&r, 0, sizeof r);
    snprintf(r.ifr_name, IFNAMSIZ, "%s", name_out);
    ioctl(s, SIOCGIFFLAGS, &r);
    r.ifr_flags |= IFF_UP;
    ioctl(s, SIOCSIFFLAGS, &r);
    close(s);
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl < 0) return -1;
    struct {
        struct nlmsghdr h;
        struct ifaddrmsg a;
        struct rtattr ra;
        uint32_t local;
        struct rtattr rb;
        uint32_t addr;
    } req;
    memset(&req, 0, sizeof req);
    req.h.nlmsg_len = sizeof req;
    req.h.nlmsg_type = RTM_NEWADDR;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.h.nlmsg_seq = 1;
    req.a.ifa_family = AF_INET;
    req.a.ifa_prefixlen = 24;
    req.a.ifa_index = (unsigned)index;
    req.ra.rta_len = RTA_LENGTH(4);
    req.ra.rta_type = IFA_LOCAL;
    req.local = htonl(NS_GUEST_ADDR);
    req.rb.rta_len = RTA_LENGTH(4);
    req.rb.rta_type = IFA_ADDRESS;
    req.addr = htonl(NS_GUEST_ADDR);
    struct sockaddr_nl k = {.nl_family = AF_NETLINK};
    if (sendto(nl, &req, sizeof req, 0, (struct sockaddr *)&k, sizeof k) < 0) {
        close(nl);
        return -1;
    }
    char ack[512];
    long n = recv(nl, ack, sizeof ack, 0);
    close(nl);
    if (n < (long)sizeof(struct nlmsghdr)) return -1;
    struct nlmsghdr *h = (struct nlmsghdr *)ack;
    if (h->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(h);
        if (e->error != 0 && e->error != -EEXIST) {
            errno = -e->error;
            return -1;
        }
    }
    return 0;
}

// Bandwidth-delay: 40 ms each way. Window scaling must be negotiated and
// the transfer must beat the 64 KiB-per-RTT ceiling of an unscaled window.
static int ns_bdp(void) {
    struct rcfg cfg;
    int c = r_mode_dial(NS_HOST, NS_BDP_PORT, 1, &cfg);
    if (c < 0) return failf("ns-bdp connect", 0, 0);
    struct tcp_info ti;
    r_tcp_info(c, &ti);
    if (!ti.tcpi_snd_wscale || !ti.tcpi_rcv_wscale || !(ti.tcpi_options & TCPI_OPT_WSCALE))
        return failf("ns-bdp: window scaling not negotiated with Linux; snd/rcv wscale",
                     ti.tcpi_snd_wscale, ti.tcpi_rcv_wscale);
    char m[256];
    for (int dir = 0; dir < 2; dir++) {
        uint64_t len = cfg.v[dir];
        long t0 = r_ms();
        if (dir == 0) {
            uint64_t at;
            const char *why;
            if (r_recv_stream(c, len, cfg.v[2], 0, &at, &why)) return failf("ns-bdp download", (unsigned long)at, 0);
        } else {
            if (r_send_stream(c, len, cfg.v[2] + 1, 1 << 20) || shutdown(c, SHUT_WR) < 0)
                return failf("ns-bdp upload", 0, 0);
            char ok;
            if (read(c, &ok, 1) != 1 || ok != 'K') return failf("ns-bdp peer verdict", 0, 0);
        }
        long ms = r_ms() - t0;
        r_tcp_info(c, &ti);
        uint64_t rtt_us = ti.tcpi_rtt ? ti.tcpi_rtt : 80000;
        if (rtt_us < 80000) rtt_us = 80000; // the configured floor
        uint64_t bps = len * 1000 / (uint64_t)(ms ? ms : 1);
        uint64_t unscaled = 65535ull * 1000000 / rtt_us;
        snprintf(m, sizeof m,
                 "netserve: ns-bdp %s %llu bytes in %ld ms = %llu KB/s (64 KiB/RTT bound %llu KB/s, rtt %u us, "
                 "wscale %u/%u, rcv_space %u)\n",
                 dir ? "upload" : "download", (unsigned long long)len, ms, (unsigned long long)(bps / 1000),
                 (unsigned long long)(unscaled / 1000), ti.tcpi_rtt, ti.tcpi_snd_wscale, ti.tcpi_rcv_wscale,
                 ti.tcpi_rcv_space);
        w(m);
        if (bps < 2 * unscaled)
            return failf(dir ? "ns-bdp upload capped near 64 KiB/RTT; B/s, bound"
                             : "ns-bdp download capped near 64 KiB/RTT; B/s, bound",
                         (unsigned long)bps, (unsigned long)unscaled);
    }
    close(c);
    w("netserve-ns-bdp-ok\n");
    return 0;
}

// Loss + reordering + duplication (netem on both directions), full duplex.
static int ns_loss(void) {
    struct rcfg cfg;
    int c = r_mode_dial(NS_HOST, NS_LOSS_PORT, 1, &cfg);
    if (c < 0) return failf("ns-loss connect", 0, 0);
    struct tcp_info ti;
    r_tcp_info(c, &ti);
    if (!(ti.tcpi_options & TCPI_OPT_SACK)) return failf("ns-loss: SACK not negotiated with Linux", ti.tcpi_options, 0);
    if (r_duplex(c, cfg.v[0], cfg.v[1], cfg.v[2], "ns-loss")) return 1;
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("ns-loss peer verdict", 0, 0);
    r_tcp_info(c, &ti);
    if (ti.tcpi_total_retrans == 0) return failf("ns-loss: no retransmissions under loss", 0, 0);
    close(c);
    w("netserve-ns-loss-ok\n");
    return 0;
}

// Blackouts: the peer drops everything for `v3` ms in the middle of each
// direction; RTO with back-off must carry the connection through.
static int ns_blackout(void) {
    struct rcfg cfg;
    int c = r_mode_dial(NS_HOST, NS_BLACKOUT_PORT, 1, &cfg);
    if (c < 0) return failf("ns-blackout connect", 0, 0);
    if (r_duplex(c, cfg.v[0], cfg.v[1], cfg.v[2], "ns-blackout")) return 1;
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("ns-blackout peer verdict", 0, 0);
    struct tcp_info ti;
    r_tcp_info(c, &ti);
    if (ti.tcpi_total_retrans == 0) return failf("ns-blackout: no retransmissions", 0, 0);
    close(c);
    w("netserve-ns-blackout-ok\n");
    return 0;
}

// Keepalive against a peer that vanished (100% loss): the read must fail
// with ETIMEDOUT after idle + cnt * intvl (Linux `tcp_keepalive_timer`).
static int ns_keepalive(void) {
    struct rcfg cfg;
    int c = r_mode_dial(NS_HOST, NS_KEEPALIVE_PORT, 1, &cfg);
    if (c < 0) return failf("ns-keepalive connect", 0, 0);
    int one = 1, idle = 2, intvl = 1, cnt = 3;
    setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
    // The peer blackholes the link once it reads this byte.
    if (write(c, "B", 1) != 1) return failf("ns-keepalive blackhole request", 0, 0);
    char ack;
    if (read(c, &ack, 1) != 1) return failf("ns-keepalive blackhole ack", 0, 0);
    long t0 = r_ms();
    long n = read(c, &ack, 1);
    int e = errno;
    long ms = r_ms() - t0;
    char m[160];
    snprintf(m, sizeof m, "netserve: ns-keepalive dead peer: read %ld errno %d after %ld ms\n", n, e, ms);
    w(m);
    if (n != -1 || e != ETIMEDOUT) return failf("ns-keepalive: want ETIMEDOUT; got n, errno", (unsigned long)n, (unsigned long)e);
    if (ms < 4000 || ms > 15000) return failf("ns-keepalive: timeout ms outside [4000, 15000]", (unsigned long)ms, 0);
    // A second read reports EOF: the error was consumed (sock_error).
    n = read(c, &ack, 1);
    if (n != 0) return failf("ns-keepalive: read after ETIMEDOUT", (unsigned long)n, (unsigned long)errno);
    close(c);
    w("netserve-ns-keepalive-ok\n");
    return 0;
}

// Resets with a peer that reports exactly what reached it.
static int ns_rst(void) {
    struct rcfg cfg;
    char m[200];
    // 1. SO_LINGER {1, 0} close mid-download: an RST, never a FIN.
    int c = r_mode_dial(NS_HOST, NS_RST_PORT, 1, &cfg);
    if (c < 0) return failf("ns-rst 1 connect", 0, 0);
    uint64_t at;
    const char *why;
    if (r_recv_stream(c, 1 << 20, cfg.v[0], 0, &at, &why)) return failf("ns-rst 1 read", (unsigned long)at, 0);
    struct linger lg = {1, 0};
    setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(c);
    // 2. close() with unread data: Linux `tcp_close` sends an RST.
    c = r_mode_dial(NS_HOST, NS_RST_PORT, 2, &cfg);
    if (c < 0) return failf("ns-rst 2 connect", 0, 0);
    char go;
    if (read(c, &go, 1) != 1) return failf("ns-rst 2 sync", 0, 0);
    r_sleep_ms(300); // let the peer's 64 KiB arrive unread
    close(c);
    // 3. The peer aborts mid-transfer: ECONNRESET once, then EOF; a write
    //    afterwards is EPIPE.
    c = r_mode_dial(NS_HOST, NS_RST_PORT, 3, &cfg);
    if (c < 0) return failf("ns-rst 3 connect", 0, 0);
    signal(SIGPIPE, SIG_IGN);
    static uint8_t buf[65536];
    uint64_t got = 0;
    long n;
    for (;;) {
        n = read(c, buf, sizeof buf);
        if (n <= 0) break;
        if (rcheck(buf, (size_t)n, got, cfg.v[0]) >= 0) return failf("ns-rst 3 byte mismatch", got, 0);
        got += (uint64_t)n;
    }
    int e = errno;
    snprintf(m, sizeof m, "netserve: ns-rst peer abort after %llu bytes: read %ld errno %d\n",
             (unsigned long long)got, n, n < 0 ? e : 0);
    w(m);
    if (n != -1 || e != ECONNRESET) return failf("ns-rst 3: want ECONNRESET; got n, errno", (unsigned long)n, (unsigned long)e);
    n = read(c, buf, 1);
    if (n != 0) return failf("ns-rst 3: read after ECONNRESET", (unsigned long)n, (unsigned long)errno);
    n = write(c, buf, 1);
    if (n != -1 || errno != EPIPE) return failf("ns-rst 3: write after reset", (unsigned long)n, (unsigned long)errno);
    close(c);
    // The peer's verdict on 1 and 2.
    c = r_mode_dial(NS_HOST, NS_RST_PORT, 4, &cfg);
    if (c < 0) return failf("ns-rst verdict connect", 0, 0);
    if (read(c, &go, 1) != 1 || go != 'K') return failf("ns-rst: the peer did not see the expected resets", 0, 0);
    close(c);
    w("netserve-ns-rst-ok\n");
    return 0;
}

// Zero windows both ways against Linux: we pause reading (Linux persists),
// then Linux pauses reading (we persist).
static int ns_zwin(void) {
    struct rcfg cfg;
    int c = r_mode_dial(NS_HOST, NS_ZWIN_PORT, 1, &cfg);
    if (c < 0) return failf("ns-zwin connect", 0, 0);
    static uint8_t buf[65536];
    uint64_t got = 0, total = cfg.v[0];
    int pauses = 0;
    while (got < total) {
        long n = read(c, buf, sizeof buf);
        if (n <= 0) return failf("ns-zwin read", got, 0);
        if (rcheck(buf, (size_t)n, got, cfg.v[2]) >= 0) return failf("ns-zwin byte mismatch", got, 0);
        got += (uint64_t)n;
        if (got / (total / 4) > (uint64_t)pauses && pauses < 3) {
            pauses++;
            r_sleep_ms((long)cfg.v[3]);
        }
    }
    if (r_send_stream(c, cfg.v[1], cfg.v[2] + 1, 1 << 20) || shutdown(c, SHUT_WR) < 0)
        return failf("ns-zwin upload", 0, 0);
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("ns-zwin peer verdict", 0, 0);
    close(c);
    w("netserve-ns-zwin-ok\n");
    return 0;
}

// Sequence wrap with loss aimed at the wrap: the peer drops a share of the
// segments whose sequence numbers are within 1 MiB of 2^32 (both
// directions), so retransmissions straddle the wrap.
static int ns_wrap(void) {
    struct rcfg cfg;
    int c = r_mode_dial(NS_HOST, NS_WRAP_PORT, 1, &cfg);
    if (c < 0) return failf("ns-wrap connect", 0, 0);
    if (r_duplex(c, cfg.v[0], cfg.v[1], cfg.v[2], "ns-wrap")) return 1;
    char ok;
    if (read(c, &ok, 1) != 1 || ok != 'K') return failf("ns-wrap peer verdict", 0, 0);
    close(c);
    w("netserve-ns-wrap-ok\n");
    return 0;
}

static void *diag_thread(void *arg) {
    (void)arg;
    for (int i = 0;; i++) {
        r_sleep_ms(10000);
        char m[64];
        snprintf(m, sizeof m, "DIAG tick %d\n", i);
        w(m);
        r_dump_tcp();
    }
    return 0;
}

static int robust_phases(void) {
    { pthread_t dt; pthread_create(&dt, 0, diag_thread, 0); }
    int ctl = r_dial(NETSERVE_HOST, R_CTRL_PORT);
    if (ctl < 0) return failf("robust control connect", 0, 0);
    struct rcfg cfg;
    if (r_cfg(ctl, &cfg)) return failf("robust control config", 0, 0);
    close(ctl);
    // v0: bitmask of SLIRP phases; v1: bitmask of namespace phases.
    uint64_t slirp = cfg.v[0], ns = cfg.v[1];
#define R_PHASE(mask, bit, name, fn)                     \
    if ((mask) & (bit)) {                                \
        w("netserve: robust phase " name "\n");          \
        if (fn()) return 1;                              \
    }
    R_PHASE(slirp, 1, "wrap", r_wrap)
    R_PHASE(slirp, 2, "zwin-rx", r_zwin_rx)
    R_PHASE(slirp, 4, "zwin-tx", r_zwin_tx)
    R_PHASE(slirp, 8, "bigio", r_bigio)
    R_PHASE(slirp, 16, "churn", r_churn)
    R_PHASE(slirp, 32, "misc", r_misc)
    if (ns) {
        char name[IFNAMSIZ] = {0};
        if (ns_config_iface(name)) return failf("ns: configuring 10.0.3.15 on the second NIC", 0, 0);
        char m[96];
        snprintf(m, sizeof m, "netserve: ns iface %s = 10.0.3.15/24\n", name);
        w(m);
        R_PHASE(ns, 1, "ns-bdp", ns_bdp)
        R_PHASE(ns, 2, "ns-loss", ns_loss)
        R_PHASE(ns, 4, "ns-blackout", ns_blackout)
        R_PHASE(ns, 8, "ns-keepalive", ns_keepalive)
        R_PHASE(ns, 16, "ns-rst", ns_rst)
        R_PHASE(ns, 32, "ns-zwin", ns_zwin)
        R_PHASE(ns, 64, "ns-wrap", ns_wrap)
    } else {
        w("netserve: namespace phases skipped (no unprivileged user+net namespace on the host)\n");
    }
    w("netserve-robust-ok\n");
    return 0;
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        w("netserve-fail: socket\n");
        return 1;
    }
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7777);
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0 — any iface

    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
        w("netserve-fail: bind\n");
        return 1;
    }
    if (listen(s, 4) < 0) {
        w("netserve-fail: listen\n");
        return 1;
    }
    w("netserve: listening on 0.0.0.0:7777\n");

    int c = accept(s, 0, 0);
    if (c < 0) {
        w("netserve-fail: accept\n");
        return 1;
    }
    w("netserve: accepted connection\n");

    char buf[512];
    long n = read(c, buf, sizeof buf);
    if (n <= 0) {
        w("netserve-fail: read\n");
        return 1;
    }
    // Echo the received bytes straight back to the client.
    long off = 0;
    while (off < n) {
        long m = write(c, buf + off, (size_t)(n - off));
        if (m <= 0) {
            w("netserve-fail: write\n");
            return 1;
        }
        off += m;
    }
    close(c);
    close(s);
    w("netserve-tcp-ok\n");

    if (bulk_echo() || download() || parallel_downloads()) return 1;

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) {
        w("netserve-fail: udp socket\n");
        return 1;
    }
    struct timeval timeout = { .tv_sec = 20, .tv_usec = 0 };
    if (setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) {
        w("netserve-fail: udp timeout\n");
        return 1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7778);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(u, (struct sockaddr *)&addr, sizeof addr) < 0) {
        w("netserve-fail: udp bind\n");
        return 1;
    }
    w("netserve: udp listening on 0.0.0.0:7778\n");

    // Echo every datagram the host sends: the single hello, the sized set
    // (1..8000 bytes; 4000 and 8000 exceed the 1500-byte MTU, so they arrive
    // and are sent back as IPv4 fragments), then the back-to-back burst.
    // Message boundaries must survive: each echo is exactly what arrived.
    static const unsigned udp_sizes[] = {1, 100, 512, 1400, 1472, 4000, 8000};
    unsigned udp_total = 1 + sizeof udp_sizes / sizeof udp_sizes[0] + UDP_BURST;
    for (unsigned i = 0; i < udp_total; i++) {
        static char udp_buf[65536];
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof peer;
        long udp_n = recvfrom(u, udp_buf, sizeof udp_buf, 0,
                              (struct sockaddr *)&peer, &peer_len);
        if (udp_n <= 0) return failf("udp recvfrom datagram", i, 0);
        if (sendto(u, udp_buf, (size_t)udp_n, 0,
                   (struct sockaddr *)&peer, peer_len) != udp_n)
            return failf("udp sendto datagram", i, (unsigned long)udp_n);
    }
    close(u);
    w("netserve-udp-ok\n");

    if (udp_client() || udp_gso_client()) return 1;

    // A minimal RFC 1035 query for example.com IN A. We issue it directly
    // instead of consulting /etc/resolv.conf so the smoke is independent of
    // the tiny boot-init filesystem while still testing the real DNS proxy.
    static const uint8_t dns_query[] = {
        0x4e, 0x41,             // transaction ID
        0x01, 0x00,             // recursion desired
        0x00, 0x01,             // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01,             // QTYPE A
        0x00, 0x01,             // QCLASS IN
    };
    int d = socket(AF_INET, SOCK_DGRAM, 0);
    if (d < 0) {
        w("netserve-fail: dns socket\n");
        return 1;
    }
    if (setsockopt(d, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) {
        w("netserve-fail: dns timeout\n");
        return 1;
    }
    struct sockaddr_in dns;
    memset(&dns, 0, sizeof dns);
    dns.sin_family = AF_INET;
    dns.sin_port = htons(53);
    if (inet_pton(AF_INET, "10.0.2.3", &dns.sin_addr) != 1) {
        w("netserve-fail: dns address\n");
        return 1;
    }
    if (sendto(d, dns_query, sizeof dns_query, 0,
               (struct sockaddr *)&dns, sizeof dns) != (long)sizeof dns_query) {
        w("netserve-fail: dns sendto\n");
        return 1;
    }
    uint8_t dns_reply[512];
    long dns_n = recvfrom(d, dns_reply, sizeof dns_reply, 0, 0, 0);
    close(d);
    if (dns_n < 12) {
        w("netserve-fail: dns recvfrom\n");
        return 1;
    }
    unsigned answers = ((unsigned)dns_reply[6] << 8) | dns_reply[7];
    if (dns_reply[0] != 0x4e || dns_reply[1] != 0x41 ||
        (dns_reply[2] & 0x80) == 0 || (dns_reply[3] & 0x0f) != 0 ||
        answers == 0) {
        w("netserve-fail: dns response\n");
        return 1;
    }
    w("netserve-dns-ok\n");
    if (icmp_checks()) return 1;
    if (robust_phases()) return 1;
    w("netserve-ok\n");
    return 0;
}
