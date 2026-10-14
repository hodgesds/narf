// Off-box network-stack smoke. The guest half of the live TCP/UDP/DNS test:
//
//   1. bind 0.0.0.0:7777, accept one host-forwarded TCP connection, echo it;
//   2. bind 0.0.0.0:7779, accept a host-forwarded bulk stream, verify every
//      byte of a known pattern and echo it all back (the host verifies the
//      echo) — GRO merging, receive windows and ACK pacing both ways;
//   3. as a CLIENT, non-blocking connect() to the host (10.0.2.2:17780) and
//      download a large patterned stream to EOF through poll() — the browser
//      shape (Firefox/Chromium sockets are non-blocking + poll/epoll);
//   4. bind 0.0.0.0:7778 and echo host datagrams of many sizes, including
//      ones above the MTU that arrive and leave as IPv4 fragments, then a
//      back-to-back burst;
//   5. as a CLIENT, a connect()ed UDP socket round-trips datagrams with the
//      host (10.0.2.2:17781) via send()/recv() — the QUIC socket shape;
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
//   * "netserve: udp listening" / "netserve-udp-ok" — UDP echo (4).
//   * "netserve-udp-client-ok" — connected UDP client (5).
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

#define BULK_LEN (4u << 20)
#define BULK_SEED 0x5a
#define DOWNLOAD_LEN (8u << 20)
#define DOWNLOAD_SEED 0xc3
#define UDP_BURST 64
#define UDP_BURST_LEN 1200
#define UDP_CLIENT_ROUNDS 16
#define UDP_CLIENT_LEN 1200

static void w(const char *m) { write(1, m, strlen(m)); }

static int failf(const char *what, unsigned long a, unsigned long b) {
    char buf[160];
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
    inet_pton(AF_INET, "10.0.2.2", &a->sin_addr); // SLIRP's alias for the host
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

    if (bulk_echo() || download()) return 1;

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

    if (udp_client()) return 1;

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
    w("netserve-ok\n");
    return 0;
}
