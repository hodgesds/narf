// Off-box network-stack smoke. The guest half of the live TCP/UDP/DNS test:
//
//   1. bind 0.0.0.0:7777, accept one host-forwarded TCP connection, echo it;
//   2. bind 0.0.0.0:7778, echo one host-forwarded UDP datagram;
//   3. send a DNS A query to QEMU SLIRP's resolver at 10.0.2.3 and validate
//      the reply header.
//
// These exercise the full socket -> route/ARP -> virtio-net paths against
// genuine off-box peers, not loopback or synthetic packet injection.
//
// Tokens on the serial console:
//   * "netserve: listening" — emitted after TCP listen(), BEFORE accept().
//     The host-side harness waits for this before opening its socket.
//   * "netserve-tcp-ok"     — after the TCP echo round-trip.
//   * "netserve-udp-ok"     — after the UDP echo round-trip.
//   * "netserve-dns-ok"     — after a valid DNS response.
//   * "netserve-ok"         — all three paths passed.
//
// Build: the uniform musl-demo recipe (musl-gcc -O2 -fPIE -pie).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void w(const char *m) { write(1, m, strlen(m)); }

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

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof peer;
    char udp_buf[512];
    long udp_n = recvfrom(u, udp_buf, sizeof udp_buf, 0,
                          (struct sockaddr *)&peer, &peer_len);
    if (udp_n <= 0) {
        w("netserve-fail: udp recvfrom\n");
        return 1;
    }
    if (sendto(u, udp_buf, (size_t)udp_n, 0,
               (struct sockaddr *)&peer, peer_len) != udp_n) {
        w("netserve-fail: udp sendto\n");
        return 1;
    }
    close(u);
    w("netserve-udp-ok\n");

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
    w("netserve-ok\n");
    return 0;
}
