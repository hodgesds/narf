// setsockopt/getsockopt parity for the option sequences network daemons run
// at startup, checked value-by-value and errno-by-errno against Linux.
//
// On a CachyOS guest NARF answered ENOPROTOOPT ("Protocol not available")
// for options every Linux kernel accepts, and each daemon gave up:
//
//   systemd-resolved  LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_LOOP
//                     (resolved-llmnr.c manager_llmnr_ipv4_udp_fd)
//   avahi-daemon      IP_MULTICAST_LOOP failed / IPV6_MULTICAST_HOPS failed
//                     (avahi-core/socket.c avahi_open_socket_ipv{4,6})
//   systemd-userdbd   Failed to set SO_RCVTIMEO (userdbd-manager.c
//                     manager_startup, on the AF_UNIX listener; the workers
//                     rely on accept() timing out with EAGAIN to exit idle)
//
// Each daemon's sequence is replayed in its own order below (ports are
// moved off 5353/5355 so a host running avahi/resolved can run the smoke),
// followed by the Linux errno contract for invalid lengths, values, levels
// and socket types (net/ipv4/ip_sockglue.c do_ip_{set,get}sockopt,
// net/ipv6/ipv6_sockglue.c do_ipv6_{set,get}sockopt, net/core/sock.c
// sk_{set,get}sockopt / sock_set_timeout / sock_get_timeout), and the
// behaviour the options promise: SO_RCVTIMEO/SO_SNDTIMEO bound blocking
// recv/accept/send with EAGAIN, and IP_MULTICAST_LOOP decides whether a
// multicast send is looped back to local members.
//
// Success token "sockopt-daemon-ok"; a failure prints
// "sockopt-daemon-fail: <case> ..." and exits 1.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

// Numeric option names, so musl and glibc headers cannot disagree about
// which layout the smoke exercises.
#define X_SO_DEBUG 1
#define X_SO_DONTROUTE 5
#define X_SO_OOBINLINE 10
#define X_SO_NO_CHECK 11
#define X_SO_PRIORITY 12
#define X_SO_PASSCRED 16
#define X_SO_RCVLOWAT 18
#define X_SO_SNDLOWAT 19
#define X_SO_RCVTIMEO_OLD 20
#define X_SO_SNDTIMEO_OLD 21
#define X_SO_DETACH_FILTER 27
#define X_SO_MARK 36
#define X_SO_INCOMING_CPU 49
#define X_SO_BINDTOIFINDEX 62
#define X_SO_RCVTIMEO_NEW 66
#define X_SO_SNDTIMEO_NEW 67
#define X_SO_TXREHASH 74

#define X_IP_RECVERR 11
#define X_IP_MTU_DISCOVER 10
#define X_IP_PMTUDISC_DONT 0
#define X_IP_PMTUDISC_OMIT 5
#define X_IP_FREEBIND 15
#define X_IP_TRANSPARENT 19
#define X_IP_RECVFRAGSIZE 25
#define X_IP_MULTICAST_IF 32
#define X_IP_MULTICAST_TTL 33
#define X_IP_MULTICAST_LOOP 34
#define X_IP_ADD_MEMBERSHIP 35
#define X_IP_DROP_MEMBERSHIP 36
#define X_IP_MULTICAST_ALL 49
#define X_IP_UNICAST_IF 50

#define X_IPV6_UNICAST_HOPS 16
#define X_IPV6_MULTICAST_IF 17
#define X_IPV6_MULTICAST_HOPS 18
#define X_IPV6_MULTICAST_LOOP 19
#define X_IPV6_ADD_MEMBERSHIP 20
#define X_IPV6_DROP_MEMBERSHIP 21
#define X_IPV6_MTU 24
#define X_IPV6_RECVERR 25
#define X_IPV6_V6ONLY 26
#define X_IPV6_MULTICAST_ALL 29
#define X_IPV6_RECVPKTINFO 49
#define X_IPV6_RECVHOPLIMIT 51
#define X_IPV6_TCLASS 67
#define X_IPV6_UNICAST_IF 76
#define X_IPV6_RECVFRAGSIZE 77
#define X_IPV6_FREEBIND 78

#define LLMNR_TEST_PORT 45355
#define MDNS_TEST_PORT 45353

static const char *current = "setup";

#define FAIL(...)                                                              \
    do {                                                                       \
        printf("sockopt-daemon-fail: %s: ", current);                         \
        printf(__VA_ARGS__);                                                   \
        printf("\n");                                                          \
        fflush(stdout);                                                        \
        exit(1);                                                               \
    } while (0)

// setsockopt must return `want` (0 = success, else that errno).
static void set_expect(int fd, int level, int name, const void *val, socklen_t len, int want,
                       const char *what) {
    errno = 0;
    int r = setsockopt(fd, level, name, val, len);
    int got = r == 0 ? 0 : errno;
    if (got != want)
        FAIL("setsockopt(%s, len=%u) = %d errno=%d, want errno=%d", what, (unsigned)len, r, got,
             want);
}

static void set_int(int fd, int level, int name, int v, const char *what) {
    set_expect(fd, level, name, &v, sizeof(v), 0, what);
}

static void set_uchar(int fd, int level, int name, unsigned char v, const char *what) {
    set_expect(fd, level, name, &v, sizeof(v), 0, what);
}

// getsockopt with a full int buffer must succeed and report `want`.
static void get_int_expect(int fd, int level, int name, int want, const char *what) {
    int v = 0x5a5a5a5a;
    socklen_t len = sizeof(v);
    if (getsockopt(fd, level, name, &v, &len) != 0)
        FAIL("getsockopt(%s) errno=%d", what, errno);
    if (len != sizeof(int))
        FAIL("getsockopt(%s) optlen=%u, want 4", what, (unsigned)len);
    if (v != want)
        FAIL("getsockopt(%s) = %d, want %d", what, v, want);
}

static void get_errno_expect(int fd, int level, int name, int want, const char *what) {
    int v = 0;
    socklen_t len = sizeof(v);
    errno = 0;
    int r = getsockopt(fd, level, name, &v, &len);
    int got = r == 0 ? 0 : errno;
    if (got != want)
        FAIL("getsockopt(%s) = %d errno=%d, want errno=%d", what, r, got, want);
}

static int must_socket(int domain, int type, int proto) {
    int fd = socket(domain, type, proto);
    if (fd < 0)
        FAIL("socket(%d, %d, %d) errno=%d", domain, type, proto, errno);
    return fd;
}

static void bind_any4(int fd, int port) {
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
        FAIL("bind(0.0.0.0:%d) errno=%d", port, errno);
}

static void bind_any6(int fd, int port) {
    struct sockaddr_in6 sa = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
        FAIL("bind([::]:%d) errno=%d", port, errno);
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// ── systemd-resolved: resolved-llmnr.c / resolved-mdns.c / resolved-dns-scope.c ──

static void resolved_llmnr_ipv4_udp(void) {
    current = "resolved/llmnr-ipv4-udp";
    int s = must_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_int(s, IPPROTO_IP, IP_PKTINFO, 1, "IP_PKTINFO");                 // socket_set_recvpktinfo
    set_int(s, IPPROTO_IP, IP_RECVTTL, 1, "IP_RECVTTL");                 // socket_set_recvttl
    set_int(s, IPPROTO_IP, IP_TTL, 255, "IP_TTL");                       // socket_set_ttl
    set_int(s, IPPROTO_IP, X_IP_MULTICAST_TTL, 255, "IP_MULTICAST_TTL");
    set_int(s, IPPROTO_IP, X_IP_MULTICAST_LOOP, 1, "IP_MULTICAST_LOOP");
    set_int(s, IPPROTO_IP, X_IP_MTU_DISCOVER, X_IP_PMTUDISC_DONT, "IP_MTU_DISCOVER");
    bind_any4(s, LLMNR_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    get_int_expect(s, IPPROTO_IP, IP_PKTINFO, 1, "IP_PKTINFO");
    get_int_expect(s, IPPROTO_IP, IP_RECVTTL, 1, "IP_RECVTTL");
    get_int_expect(s, IPPROTO_IP, IP_TTL, 255, "IP_TTL");
    get_int_expect(s, IPPROTO_IP, X_IP_MULTICAST_TTL, 255, "IP_MULTICAST_TTL");
    get_int_expect(s, IPPROTO_IP, X_IP_MULTICAST_LOOP, 1, "IP_MULTICAST_LOOP");
    get_int_expect(s, IPPROTO_IP, X_IP_MTU_DISCOVER, X_IP_PMTUDISC_DONT, "IP_MTU_DISCOVER");
    get_int_expect(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    // dns_scope_multicast_membership(): join the LLMNR group on the link.
    struct ip_mreqn mreqn = {.imr_ifindex = 1};
    mreqn.imr_multiaddr.s_addr = htonl(0xE00000FC); // 224.0.0.252
    (void)setsockopt(s, IPPROTO_IP, X_IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn));
    set_expect(s, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn), 0, "IP_ADD_MEMBERSHIP");
    set_expect(s, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn), EADDRINUSE,
               "IP_ADD_MEMBERSHIP twice");
    set_expect(s, IPPROTO_IP, X_IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn), 0,
               "IP_DROP_MEMBERSHIP");
    set_expect(s, IPPROTO_IP, X_IP_DROP_MEMBERSHIP, &mreqn, sizeof(mreqn), EADDRNOTAVAIL,
               "IP_DROP_MEMBERSHIP not a member");
    close(s);
}

static void resolved_llmnr_ipv6_udp(void) {
    current = "resolved/llmnr-ipv6-udp";
    int s = must_socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVPKTINFO, 1, "IPV6_RECVPKTINFO");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVHOPLIMIT, 1, "IPV6_RECVHOPLIMIT");
    set_int(s, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 255, "IPV6_UNICAST_HOPS");
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 255, "IPV6_MULTICAST_HOPS");
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 1, "IPV6_MULTICAST_LOOP");
    set_int(s, IPPROTO_IPV6, X_IPV6_V6ONLY, 1, "IPV6_V6ONLY");
    bind_any6(s, LLMNR_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 255, "IPV6_UNICAST_HOPS");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 255, "IPV6_MULTICAST_HOPS");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 1, "IPV6_MULTICAST_LOOP");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_V6ONLY, 1, "IPV6_V6ONLY");
    struct ipv6_mreq m6 = {.ipv6mr_interface = 1};
    m6.ipv6mr_multiaddr.s6_addr[0] = 0xff;
    m6.ipv6mr_multiaddr.s6_addr[1] = 0x02;
    m6.ipv6mr_multiaddr.s6_addr[13] = 0x01;
    m6.ipv6mr_multiaddr.s6_addr[14] = 0x00;
    m6.ipv6mr_multiaddr.s6_addr[15] = 0x03; // ff02::1:3
    (void)setsockopt(s, IPPROTO_IPV6, X_IPV6_DROP_MEMBERSHIP, &m6, sizeof(m6));
    set_expect(s, IPPROTO_IPV6, X_IPV6_ADD_MEMBERSHIP, &m6, sizeof(m6), 0, "IPV6_ADD_MEMBERSHIP");
    set_expect(s, IPPROTO_IPV6, X_IPV6_ADD_MEMBERSHIP, &m6, sizeof(m6), EADDRINUSE,
               "IPV6_ADD_MEMBERSHIP twice");
    set_expect(s, IPPROTO_IPV6, X_IPV6_DROP_MEMBERSHIP, &m6, sizeof(m6), 0,
               "IPV6_DROP_MEMBERSHIP");
    set_expect(s, IPPROTO_IPV6, X_IPV6_DROP_MEMBERSHIP, &m6, sizeof(m6), EADDRNOTAVAIL,
               "IPV6_DROP_MEMBERSHIP not a member");
    close(s);
}

static void resolved_llmnr_tcp(void) {
    current = "resolved/llmnr-ipv4-tcp";
    int s = must_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_int(s, IPPROTO_IP, IP_PKTINFO, 1, "IP_PKTINFO");
    set_int(s, IPPROTO_IP, IP_RECVTTL, 1, "IP_RECVTTL");
    set_int(s, IPPROTO_IP, IP_TTL, 1, "IP_TTL");
    int five = 5;
    (void)setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &five, sizeof(five)); // ignored by resolved
    set_int(s, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY");
    set_int(s, IPPROTO_IP, X_IP_MTU_DISCOVER, X_IP_PMTUDISC_DONT, "IP_MTU_DISCOVER");
    bind_any4(s, LLMNR_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    if (listen(s, 16) != 0)
        FAIL("listen errno=%d", errno);
    get_int_expect(s, IPPROTO_IP, IP_TTL, 1, "IP_TTL");
    // IP_MULTICAST_TTL is refused on a stream socket (EINVAL), and
    // IPV6_MULTICAST_HOPS on a v6 stream socket is ENOPROTOOPT.
    set_expect(s, IPPROTO_IP, X_IP_MULTICAST_TTL, &five, sizeof(five), EINVAL,
               "IP_MULTICAST_TTL on TCP");
    struct ip_mreqn m = {.imr_ifindex = 1};
    m.imr_multiaddr.s_addr = htonl(0xE00000FC);
    set_expect(s, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &m, sizeof(m), EPROTO,
               "IP_ADD_MEMBERSHIP on TCP");
    close(s);

    current = "resolved/llmnr-ipv6-tcp";
    s = must_socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_int(s, IPPROTO_IPV6, X_IPV6_V6ONLY, 1, "IPV6_V6ONLY");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVPKTINFO, 1, "IPV6_RECVPKTINFO");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVHOPLIMIT, 1, "IPV6_RECVHOPLIMIT");
    set_int(s, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 1, "IPV6_UNICAST_HOPS");
    set_int(s, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY");
    bind_any6(s, LLMNR_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    if (listen(s, 16) != 0)
        FAIL("listen errno=%d", errno);
    set_expect(s, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, &five, sizeof(five), ENOPROTOOPT,
               "IPV6_MULTICAST_HOPS on TCP");
    set_expect(s, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, &five, sizeof(five), ENOPROTOOPT,
               "IPV6_MULTICAST_IF on TCP");
    close(s);
}

static void resolved_mdns(void) {
    current = "resolved/mdns-ipv4";
    int s = must_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_int(s, IPPROTO_IP, IP_TTL, 255, "IP_TTL");
    set_int(s, IPPROTO_IP, X_IP_MULTICAST_TTL, 255, "IP_MULTICAST_TTL");
    set_int(s, IPPROTO_IP, X_IP_MULTICAST_LOOP, 1, "IP_MULTICAST_LOOP");
    set_int(s, IPPROTO_IP, IP_PKTINFO, 1, "IP_PKTINFO");
    set_int(s, IPPROTO_IP, IP_RECVTTL, 1, "IP_RECVTTL");
    set_int(s, IPPROTO_IP, X_IP_MTU_DISCOVER, X_IP_PMTUDISC_DONT, "IP_MTU_DISCOVER");
    bind_any4(s, MDNS_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    close(s);

    current = "resolved/mdns-ipv6";
    s = must_socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_int(s, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 255, "IPV6_UNICAST_HOPS");
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 255, "IPV6_MULTICAST_HOPS");
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 1, "IPV6_MULTICAST_LOOP");
    set_int(s, IPPROTO_IPV6, X_IPV6_V6ONLY, 1, "IPV6_V6ONLY");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVPKTINFO, 1, "IPV6_RECVPKTINFO");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVHOPLIMIT, 1, "IPV6_RECVHOPLIMIT");
    bind_any6(s, MDNS_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    close(s);
}

// resolved-dns-scope.c dns_scope_socket() + resolved-manager.c
// manager_dns_stub / socket_disable_pmtud for a per-link DNS UDP socket.
static void resolved_dns_scope(void) {
    current = "resolved/dns-scope-ipv4";
    int s = must_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    uint32_t ifindex_be = htonl(1);
    set_expect(s, IPPROTO_IP, X_IP_UNICAST_IF, &ifindex_be, sizeof(ifindex_be), 0,
               "IP_UNICAST_IF");
    get_int_expect(s, IPPROTO_IP, X_IP_UNICAST_IF, (int)htonl(1), "IP_UNICAST_IF");
    set_int(s, IPPROTO_IP, IP_TTL, 1, "IP_TTL");
    set_int(s, IPPROTO_IP, X_IP_RECVERR, 1, "IP_RECVERR");
    get_int_expect(s, IPPROTO_IP, X_IP_RECVERR, 1, "IP_RECVERR");
    set_int(s, IPPROTO_IP, IP_PKTINFO, 1, "IP_PKTINFO");
    set_int(s, IPPROTO_IP, X_IP_RECVFRAGSIZE, 1, "IP_RECVFRAGSIZE");
    get_int_expect(s, IPPROTO_IP, X_IP_RECVFRAGSIZE, 1, "IP_RECVFRAGSIZE");
    set_int(s, IPPROTO_IP, X_IP_MTU_DISCOVER, X_IP_PMTUDISC_OMIT, "IP_MTU_DISCOVER OMIT");
    get_int_expect(s, IPPROTO_IP, X_IP_MTU_DISCOVER, X_IP_PMTUDISC_OMIT, "IP_MTU_DISCOVER");
    set_int(s, IPPROTO_IP, X_IP_FREEBIND, 1, "IP_FREEBIND");
    get_int_expect(s, IPPROTO_IP, X_IP_FREEBIND, 1, "IP_FREEBIND");
    // FREEBIND and TRANSPARENT are separate bits in Linux.
    get_int_expect(s, IPPROTO_IP, X_IP_TRANSPARENT, 0, "IP_TRANSPARENT after FREEBIND");
    close(s);

    current = "resolved/dns-scope-ipv6";
    s = must_socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_expect(s, IPPROTO_IPV6, X_IPV6_UNICAST_IF, &ifindex_be, sizeof(ifindex_be), 0,
               "IPV6_UNICAST_IF");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_UNICAST_IF, (int)htonl(1), "IPV6_UNICAST_IF");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVERR, 1, "IPV6_RECVERR");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVFRAGSIZE, 1, "IPV6_RECVFRAGSIZE");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_RECVFRAGSIZE, 1, "IPV6_RECVFRAGSIZE");
    set_int(s, IPPROTO_IPV6, X_IPV6_MTU, 1280, "IPV6_MTU");
    set_int(s, IPPROTO_IPV6, X_IPV6_MTU, 0, "IPV6_MTU 0");
    set_int(s, IPPROTO_IPV6, X_IPV6_FREEBIND, 1, "IPV6_FREEBIND");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_FREEBIND, 1, "IPV6_FREEBIND");
    // An AF_INET6 datagram socket takes SOL_IP options (ipv6_setsockopt
    // forwards them to ip_setsockopt).
    set_int(s, IPPROTO_IP, X_IP_MULTICAST_LOOP, 0, "IP_MULTICAST_LOOP on v6");
    get_int_expect(s, IPPROTO_IP, X_IP_MULTICAST_LOOP, 0, "IP_MULTICAST_LOOP on v6");
    close(s);
}

// ── avahi-daemon: avahi-core/socket.c ──

static void avahi_ipv4(void) {
    current = "avahi/ipv4";
    int s = must_socket(AF_INET, SOCK_DGRAM, 0);
    set_uchar(s, IPPROTO_IP, X_IP_MULTICAST_TTL, 255, "IP_MULTICAST_TTL (uint8)");
    set_int(s, IPPROTO_IP, IP_TTL, 255, "IP_TTL");
    set_uchar(s, IPPROTO_IP, X_IP_MULTICAST_LOOP, 1, "IP_MULTICAST_LOOP (uint8)");
    bind_any4(s, MDNS_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    set_int(s, SOL_SOCKET, SO_REUSEPORT, 1, "SO_REUSEPORT");
    set_int(s, IPPROTO_IP, IP_PKTINFO, 1, "IP_PKTINFO");
    set_int(s, IPPROTO_IP, IP_RECVTTL, 1, "IP_RECVTTL");
    // avahi_send_dns_packet_ipv4: IP_MULTICAST_IF with the interface address.
    struct in_addr lo = {.s_addr = htonl(INADDR_LOOPBACK)};
    set_expect(s, IPPROTO_IP, X_IP_MULTICAST_IF, &lo, sizeof(lo), 0, "IP_MULTICAST_IF in_addr");
    struct in_addr got = {0};
    socklen_t len = sizeof(got);
    if (getsockopt(s, IPPROTO_IP, X_IP_MULTICAST_IF, &got, &len) != 0 || len != 4 ||
        got.s_addr != lo.s_addr)
        FAIL("getsockopt(IP_MULTICAST_IF) len=%u addr=%08x", (unsigned)len, got.s_addr);
    // A one-byte read of a small int option gets one byte (copyval).
    unsigned char c = 0;
    len = 1;
    if (getsockopt(s, IPPROTO_IP, X_IP_MULTICAST_TTL, &c, &len) != 0 || len != 1 || c != 255)
        FAIL("1-byte getsockopt(IP_MULTICAST_TTL) len=%u v=%u", (unsigned)len, c);
    // avahi_mdns_mcast_join_ipv4: drop-then-add with ip_mreqn.
    struct ip_mreqn m = {.imr_ifindex = 1};
    m.imr_address.s_addr = htonl(INADDR_LOOPBACK);
    m.imr_multiaddr.s_addr = htonl(0xE00000FB); // 224.0.0.251
    (void)setsockopt(s, IPPROTO_IP, X_IP_DROP_MEMBERSHIP, &m, sizeof(m));
    set_expect(s, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &m, sizeof(m), 0, "IP_ADD_MEMBERSHIP mreqn");
    set_expect(s, IPPROTO_IP, X_IP_DROP_MEMBERSHIP, &m, sizeof(m), 0, "IP_DROP_MEMBERSHIP mreqn");
    // struct ip_mreq (8 bytes, no ifindex) is accepted too.
    struct ip_mreq mr;
    mr.imr_multiaddr.s_addr = htonl(0xE00000FB);
    mr.imr_interface.s_addr = htonl(INADDR_LOOPBACK);
    set_expect(s, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &mr, sizeof(mr), 0, "IP_ADD_MEMBERSHIP mreq");
    set_expect(s, IPPROTO_IP, X_IP_DROP_MEMBERSHIP, &mr, sizeof(mr), 0, "IP_DROP_MEMBERSHIP mreq");
    close(s);
}

static void avahi_ipv6(void) {
    current = "avahi/ipv6";
    int s = must_socket(AF_INET6, SOCK_DGRAM, 0);
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 255, "IPV6_MULTICAST_HOPS");
    set_int(s, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 255, "IPV6_UNICAST_HOPS");
    set_int(s, IPPROTO_IPV6, X_IPV6_V6ONLY, 1, "IPV6_V6ONLY");
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 1, "IPV6_MULTICAST_LOOP");
    bind_any6(s, MDNS_TEST_PORT);
    set_int(s, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    set_int(s, SOL_SOCKET, SO_REUSEPORT, 1, "SO_REUSEPORT");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVPKTINFO, 1, "IPV6_RECVPKTINFO");
    set_int(s, IPPROTO_IPV6, X_IPV6_RECVHOPLIMIT, 1, "IPV6_RECVHOPLIMIT");
    // avahi_send_dns_packet_ipv6 picks the interface per packet; the sticky
    // IPV6_MULTICAST_IF must accept a live ifindex and 0.
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, 1, "IPV6_MULTICAST_IF lo");
    get_int_expect(s, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, 1, "IPV6_MULTICAST_IF");
    set_int(s, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, 0, "IPV6_MULTICAST_IF 0");
    close(s);
}

// ── systemd-userdbd: userdbd-manager.c manager_startup + userwork.c ──

static void userdbd_listener_timeout(void) {
    current = "userdbd/so_rcvtimeo-accept";
    int s = must_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path + 1, sizeof(sa.sun_path) - 1, "sockopt-daemon-%d", (int)getpid());
    socklen_t salen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sa.sun_path + 1);
    if (bind(s, (struct sockaddr *)&sa, salen) != 0)
        FAIL("bind(abstract) errno=%d", errno);
    if (listen(s, 16) != 0)
        FAIL("listen errno=%d", errno);
    // userdbd sets 25 s; the smoke uses 300 ms so the timeout is observable.
    struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &tv, sizeof(tv), 0, "SO_RCVTIMEO");
    struct timeval back = {-1, -1};
    socklen_t len = sizeof(back);
    if (getsockopt(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &back, &len) != 0 || len != sizeof(back) ||
        back.tv_sec != 0 || back.tv_usec != 300000)
        FAIL("getsockopt(SO_RCVTIMEO) len=%u = {%ld,%ld}", (unsigned)len, (long)back.tv_sec,
             (long)back.tv_usec);
    long long t0 = now_ms();
    errno = 0;
    int c = accept4(s, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    long long dt = now_ms() - t0;
    if (c >= 0 || errno != EAGAIN)
        FAIL("blocking accept4 with SO_RCVTIMEO = %d errno=%d, want EAGAIN", c, errno);
    if (dt < 250 || dt > 5000)
        FAIL("accept4 timed out after %lld ms, want ~300", dt);
    close(s);
}

static void timeout_contract(void) {
    current = "so_rcvtimeo/contract";
    int s = must_socket(AF_INET, SOCK_DGRAM, 0);
    // Default: no timeout, reported as {0, 0}, in both layouts.
    struct {
        long long sec, usec;
    } nt = {-1, -1};
    socklen_t len = sizeof(nt);
    if (getsockopt(s, SOL_SOCKET, X_SO_SNDTIMEO_NEW, &nt, &len) != 0 || len != 16 || nt.sec != 0 ||
        nt.usec != 0)
        FAIL("default SO_SNDTIMEO_NEW len=%u {%lld,%lld}", (unsigned)len, nt.sec, nt.usec);
    // sock_copy_user_timeval: short optlen → EINVAL (old and new layouts).
    struct timeval tv = {1, 0};
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &tv, 8, EINVAL, "SO_RCVTIMEO optlen 8");
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_NEW, &tv, 15, EINVAL, "SO_RCVTIMEO_NEW optlen 15");
    set_expect(s, SOL_SOCKET, X_SO_SNDTIMEO_OLD, &tv, 3, EINVAL, "SO_SNDTIMEO optlen 3");
    // sock_set_timeout: usec out of [0, 1e6) → EDOM.
    tv.tv_usec = 1000000;
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &tv, sizeof(tv), EDOM, "SO_RCVTIMEO usec=1e6");
    tv.tv_usec = -1;
    set_expect(s, SOL_SOCKET, X_SO_SNDTIMEO_OLD, &tv, sizeof(tv), EDOM, "SO_SNDTIMEO usec=-1");
    // NEW layout round trip, read back through the OLD name.
    nt.sec = 2;
    nt.usec = 250000;
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_NEW, &nt, sizeof(nt), 0, "SO_RCVTIMEO_NEW");
    struct timeval back;
    len = sizeof(back);
    if (getsockopt(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &back, &len) != 0 || back.tv_sec != 2 ||
        back.tv_usec != 250000)
        FAIL("SO_RCVTIMEO after NEW set = {%ld,%ld}", (long)back.tv_sec, (long)back.tv_usec);
    // A short getsockopt buffer is truncated, not rejected.
    long first = -1;
    len = sizeof(first);
    if (getsockopt(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &first, &len) != 0 || len != 8 || first != 2)
        FAIL("8-byte getsockopt(SO_RCVTIMEO) len=%u sec=%ld", (unsigned)len, first);
    // {0, 0} means "no timeout".
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &tv, sizeof(tv), 0, "SO_RCVTIMEO {0,0}");
    len = sizeof(back);
    if (getsockopt(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &back, &len) != 0 || back.tv_sec != 0 ||
        back.tv_usec != 0)
        FAIL("SO_RCVTIMEO {0,0} read back {%ld,%ld}", (long)back.tv_sec, (long)back.tv_usec);
    // A negative tv_sec stores a ZERO timeout: the blocking recv returns
    // EAGAIN at once, and it reads back as {0, 0}.
    tv.tv_sec = -5;
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &tv, sizeof(tv), 0, "SO_RCVTIMEO sec<0");
    struct sockaddr_in any = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(s, (struct sockaddr *)&any, sizeof(any)) != 0)
        FAIL("bind(127.0.0.1:0) errno=%d", errno);
    char b[4];
    long long t0 = now_ms();
    errno = 0;
    ssize_t n = recv(s, b, sizeof(b), 0);
    if (n != -1 || errno != EAGAIN || now_ms() - t0 > 200)
        FAIL("recv with a zero timeout = %zd errno=%d after %lld ms", n, errno, now_ms() - t0);

    current = "so_rcvtimeo/udp-recv";
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    set_expect(s, SOL_SOCKET, X_SO_RCVTIMEO_OLD, &tv, sizeof(tv), 0, "SO_RCVTIMEO 200ms");
    t0 = now_ms();
    errno = 0;
    n = recv(s, b, sizeof(b), 0);
    long long dt = now_ms() - t0;
    if (n != -1 || errno != EAGAIN)
        FAIL("blocking recv with SO_RCVTIMEO = %zd errno=%d, want EAGAIN", n, errno);
    if (dt < 150 || dt > 5000)
        FAIL("recv timed out after %lld ms, want ~200", dt);
    // Data that is already queued is returned without waiting.
    socklen_t al = sizeof(any);
    getsockname(s, (struct sockaddr *)&any, &al);
    int tx = must_socket(AF_INET, SOCK_DGRAM, 0);
    if (sendto(tx, "hi", 2, 0, (struct sockaddr *)&any, sizeof(any)) != 2)
        FAIL("sendto loopback errno=%d", errno);
    n = recv(s, b, sizeof(b), 0);
    if (n != 2)
        FAIL("recv of a queued datagram = %zd errno=%d", n, errno);
    close(tx);
    close(s);

    current = "so_sndtimeo/unix-stream-send";
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        FAIL("socketpair errno=%d", errno);
    int small = 4096;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    static char chunk[4096];
    long total = 0;
    for (int i = 0; i < 100000; i++) {
        ssize_t w = send(sv[0], chunk, sizeof(chunk), MSG_NOSIGNAL);
        if (w < 0) {
            if (errno != EAGAIN)
                FAIL("filling send errno=%d", errno);
            break;
        }
        total += w;
    }
    fcntl(sv[0], F_SETFL, 0);
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    set_expect(sv[0], SOL_SOCKET, X_SO_SNDTIMEO_OLD, &tv, sizeof(tv), 0, "SO_SNDTIMEO 200ms");
    t0 = now_ms();
    errno = 0;
    n = send(sv[0], chunk, 1, MSG_NOSIGNAL);
    dt = now_ms() - t0;
    if (n != -1 || errno != EAGAIN)
        FAIL("blocking send into a full stream with SO_SNDTIMEO = %zd errno=%d (queued %ld)", n,
             errno, total);
    if (dt < 150 || dt > 5000)
        FAIL("send timed out after %lld ms, want ~200", dt);
    close(sv[0]);
    close(sv[1]);
}

// ── Linux errno contract for the IP / IPv6 levels ──

static void ip_contract(void) {
    current = "ip/contract";
    int u = must_socket(AF_INET, SOCK_DGRAM, 0);
    int zero = 0, big = 256, neg2 = -2, one = 1, six = 6;
    get_int_expect(u, IPPROTO_IP, X_IP_MULTICAST_LOOP, 1, "default IP_MULTICAST_LOOP");
    get_int_expect(u, IPPROTO_IP, X_IP_MULTICAST_TTL, 1, "default IP_MULTICAST_TTL");
    get_int_expect(u, IPPROTO_IP, X_IP_MULTICAST_ALL, 1, "default IP_MULTICAST_ALL");
    get_int_expect(u, IPPROTO_IP, X_IP_MTU_DISCOVER, 1, "default IP_MTU_DISCOVER (WANT)");
    get_int_expect(u, IPPROTO_IP, X_IP_UNICAST_IF, 0, "default IP_UNICAST_IF");
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_LOOP, &one, 0, EINVAL, "IP_MULTICAST_LOOP optlen 0");
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_TTL, &big, sizeof(big), EINVAL, "IP_MULTICAST_TTL 256");
    set_int(u, IPPROTO_IP, X_IP_MULTICAST_TTL, -1, "IP_MULTICAST_TTL -1");
    get_int_expect(u, IPPROTO_IP, X_IP_MULTICAST_TTL, 1, "IP_MULTICAST_TTL after -1");
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_ALL, &big, sizeof(big), EINVAL, "IP_MULTICAST_ALL 256");
    set_int(u, IPPROTO_IP, X_IP_MULTICAST_ALL, 0, "IP_MULTICAST_ALL 0");
    get_int_expect(u, IPPROTO_IP, X_IP_MULTICAST_ALL, 0, "IP_MULTICAST_ALL");
    set_expect(u, IPPROTO_IP, X_IP_MTU_DISCOVER, &six, sizeof(six), EINVAL, "IP_MTU_DISCOVER 6");
    set_expect(u, IPPROTO_IP, X_IP_MTU_DISCOVER, &neg2, sizeof(neg2), EINVAL,
               "IP_MTU_DISCOVER -2");
    // Any IP int option reads a 2-byte optval as its first byte.
    unsigned char two[2] = {0, 0xff};
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_LOOP, two, 2, 0, "IP_MULTICAST_LOOP 2-byte 0");
    get_int_expect(u, IPPROTO_IP, X_IP_MULTICAST_LOOP, 0, "IP_MULTICAST_LOOP after 2-byte 0");
    // IP_UNICAST_IF: optlen must be exactly 4; an unknown index is
    // EADDRNOTAVAIL; 0 clears it.
    uint32_t be = htonl(1);
    set_expect(u, IPPROTO_IP, X_IP_UNICAST_IF, &be, 1, EINVAL, "IP_UNICAST_IF optlen 1");
    uint32_t bogus = htonl(0x7fff0);
    set_expect(u, IPPROTO_IP, X_IP_UNICAST_IF, &bogus, 4, EADDRNOTAVAIL, "IP_UNICAST_IF bogus");
    set_expect(u, IPPROTO_IP, X_IP_UNICAST_IF, &zero, 4, 0, "IP_UNICAST_IF 0");
    // IP_MULTICAST_IF: optlen < 4 → EINVAL; an unknown ifindex →
    // EADDRNOTAVAIL; INADDR_ANY clears it.
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_IF, &zero, 3, EINVAL, "IP_MULTICAST_IF optlen 3");
    struct ip_mreqn mq = {.imr_ifindex = 0x7fff0};
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_IF, &mq, sizeof(mq), EADDRNOTAVAIL,
               "IP_MULTICAST_IF bogus ifindex");
    struct in_addr nonlocal = {.s_addr = htonl(0xC0000201)}; // 192.0.2.1 (TEST-NET-1)
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_IF, &nonlocal, 4, EADDRNOTAVAIL,
               "IP_MULTICAST_IF non-local address");
    set_expect(u, IPPROTO_IP, X_IP_MULTICAST_IF, &zero, 4, 0, "IP_MULTICAST_IF INADDR_ANY");
    // IP_ADD_MEMBERSHIP: optlen < sizeof(ip_mreq) → EINVAL, a unicast
    // group → EINVAL, no such device → ENODEV.
    struct ip_mreqn m = {.imr_ifindex = 1};
    m.imr_multiaddr.s_addr = htonl(0xE00000FB);
    set_expect(u, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &m, 7, EINVAL, "IP_ADD_MEMBERSHIP optlen 7");
    struct ip_mreqn uni = m;
    uni.imr_multiaddr.s_addr = htonl(INADDR_LOOPBACK);
    set_expect(u, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &uni, sizeof(uni), EINVAL,
               "IP_ADD_MEMBERSHIP unicast group");
    struct ip_mreqn nodev = m;
    nodev.imr_ifindex = 0x7fff0;
    set_expect(u, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &nodev, sizeof(nodev), ENODEV,
               "IP_ADD_MEMBERSHIP no device");
    // Unknown option / foreign level.
    set_expect(u, IPPROTO_IP, 199, &one, sizeof(one), ENOPROTOOPT, "IP option 199");
    get_errno_expect(u, IPPROTO_IP, 199, ENOPROTOOPT, "IP option 199");
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, &one, sizeof(one), ENOPROTOOPT,
               "IPV6 level on AF_INET");
    get_errno_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, EOPNOTSUPP, "IPV6 level on AF_INET");
    close(u);
}

static void ipv6_contract(void) {
    current = "ipv6/contract";
    int u = must_socket(AF_INET6, SOCK_DGRAM, 0);
    int one = 1, two = 2, big = 256, neg2 = -2, zero = 0;
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 1, "default IPV6_MULTICAST_LOOP");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 1, "default IPV6_MULTICAST_HOPS");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 64, "default IPV6_UNICAST_HOPS");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_ALL, 1, "default IPV6_MULTICAST_ALL");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, 0, "default IPV6_MULTICAST_IF");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_TCLASS, 0, "default IPV6_TCLASS");
    // IPV6 int options need a full int.
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, &one, 1, EINVAL,
               "IPV6_MULTICAST_LOOP optlen 1");
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, &two, sizeof(two), EINVAL,
               "IPV6_MULTICAST_LOOP 2");
    set_int(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 0, "IPV6_MULTICAST_LOOP 0");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_LOOP, 0, "IPV6_MULTICAST_LOOP");
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, &one, 3, EINVAL,
               "IPV6_MULTICAST_HOPS optlen 3");
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, &big, sizeof(big), EINVAL,
               "IPV6_MULTICAST_HOPS 256");
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, &neg2, sizeof(neg2), EINVAL,
               "IPV6_MULTICAST_HOPS -2");
    set_int(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 7, "IPV6_MULTICAST_HOPS 7");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 7, "IPV6_MULTICAST_HOPS");
    set_int(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, -1, "IPV6_MULTICAST_HOPS -1");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_HOPS, 1, "IPV6_MULTICAST_HOPS after -1");
    set_int(u, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, -1, "IPV6_UNICAST_HOPS -1");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, 64, "IPV6_UNICAST_HOPS after -1");
    set_expect(u, IPPROTO_IPV6, X_IPV6_UNICAST_HOPS, &one, 1, EINVAL,
               "IPV6_UNICAST_HOPS optlen 1");
    // IPV6_MULTICAST_IF: an unknown ifindex is ENODEV.
    int bogus = 0x7fff0;
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, &bogus, sizeof(bogus), ENODEV,
               "IPV6_MULTICAST_IF bogus");
    set_expect(u, IPPROTO_IPV6, X_IPV6_MULTICAST_IF, &one, 2, EINVAL, "IPV6_MULTICAST_IF optlen 2");
    // IPV6_UNICAST_IF: optlen exactly 4; unknown index → EADDRNOTAVAIL.
    uint32_t be_bogus = htonl(0x7fff0);
    set_expect(u, IPPROTO_IPV6, X_IPV6_UNICAST_IF, &be_bogus, 4, EADDRNOTAVAIL,
               "IPV6_UNICAST_IF bogus");
    set_expect(u, IPPROTO_IPV6, X_IPV6_UNICAST_IF, &zero, 2, EINVAL, "IPV6_UNICAST_IF optlen 2");
    // IPV6_MTU: 0 is legal, 1..1279 is EINVAL.
    int small = 1000;
    set_expect(u, IPPROTO_IPV6, X_IPV6_MTU, &small, sizeof(small), EINVAL, "IPV6_MTU 1000");
    // IPV6_TCLASS: -1 means 0, >255 is EINVAL.
    set_int(u, IPPROTO_IPV6, X_IPV6_TCLASS, 0x28, "IPV6_TCLASS 0x28");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_TCLASS, 0x28, "IPV6_TCLASS");
    set_expect(u, IPPROTO_IPV6, X_IPV6_TCLASS, &big, sizeof(big), EINVAL, "IPV6_TCLASS 256");
    set_int(u, IPPROTO_IPV6, X_IPV6_TCLASS, -1, "IPV6_TCLASS -1");
    get_int_expect(u, IPPROTO_IPV6, X_IPV6_TCLASS, 0, "IPV6_TCLASS after -1");
    // IPV6_ADD_MEMBERSHIP: short optlen → EINVAL, unknown device → ENODEV.
    struct ipv6_mreq m6 = {.ipv6mr_interface = 0x7fff0};
    m6.ipv6mr_multiaddr.s6_addr[0] = 0xff;
    m6.ipv6mr_multiaddr.s6_addr[1] = 0x02;
    m6.ipv6mr_multiaddr.s6_addr[15] = 0xfb;
    set_expect(u, IPPROTO_IPV6, X_IPV6_ADD_MEMBERSHIP, &m6, 19, EINVAL,
               "IPV6_ADD_MEMBERSHIP optlen 19");
    set_expect(u, IPPROTO_IPV6, X_IPV6_ADD_MEMBERSHIP, &m6, sizeof(m6), ENODEV,
               "IPV6_ADD_MEMBERSHIP no device");
    struct ipv6_mreq uni6 = {.ipv6mr_interface = 1};
    uni6.ipv6mr_multiaddr.s6_addr[15] = 1; // ::1 is not multicast
    set_expect(u, IPPROTO_IPV6, X_IPV6_ADD_MEMBERSHIP, &uni6, sizeof(uni6), EINVAL,
               "IPV6_ADD_MEMBERSHIP unicast group");
    // Unknown IPv6 option; a foreign level on AF_INET6 is ENOPROTOOPT for
    // both directions (ipv6_{set,get}sockopt).
    set_expect(u, IPPROTO_IPV6, 199, &one, sizeof(one), ENOPROTOOPT, "IPV6 option 199");
    get_errno_expect(u, IPPROTO_IPV6, 199, ENOPROTOOPT, "IPV6 option 199");
    get_errno_expect(u, 281 /* SOL_ALG */, 1, ENOPROTOOPT, "foreign level on AF_INET6");
    // do_ipv6_getsockopt never rejects a negative optlen (it copies
    // min_t(unsigned int, sizeof(int), len)), unlike SOL_IP / SOL_SOCKET.
    int v6only = -7;
    socklen_t neglen = (socklen_t)-1;
    if (getsockopt(u, IPPROTO_IPV6, X_IPV6_V6ONLY, &v6only, &neglen) != 0 || neglen != 4)
        FAIL("getsockopt(IPV6_V6ONLY, optlen -1) errno=%d optlen=%d", errno, (int)neglen);
    neglen = (socklen_t)-1;
    if (getsockopt(u, IPPROTO_IP, IP_TTL, &v6only, &neglen) != -1 || errno != EINVAL)
        FAIL("getsockopt(IP_TTL, optlen -1) on AF_INET6 is not EINVAL (errno=%d)", errno);
    close(u);
}

static void sol_socket_contract(void) {
    current = "sol_socket/contract";
    int u = must_socket(AF_INET, SOCK_DGRAM, 0);
    int v, one = 1, zero = 0;
    socklen_t len;
    // sk_setsockopt SO_SNDBUF/SO_RCVBUF store val*2, floored at
    // SOCK_MIN_SNDBUF / SOCK_MIN_RCVBUF.
    set_int(u, SOL_SOCKET, SO_RCVBUF, 4096, "SO_RCVBUF 4096");
    get_int_expect(u, SOL_SOCKET, SO_RCVBUF, 8192, "SO_RCVBUF doubled");
    set_int(u, SOL_SOCKET, SO_SNDBUF, 65536, "SO_SNDBUF 65536");
    get_int_expect(u, SOL_SOCKET, SO_SNDBUF, 131072, "SO_SNDBUF doubled");
    set_int(u, SOL_SOCKET, SO_RCVBUF, 0, "SO_RCVBUF 0");
    get_int_expect(u, SOL_SOCKET, SO_RCVBUF, 2304, "SO_RCVBUF floor");
    set_int(u, SOL_SOCKET, SO_SNDBUF, 0, "SO_SNDBUF 0");
    get_int_expect(u, SOL_SOCKET, SO_SNDBUF, 4608, "SO_SNDBUF floor");
    // Flags that are stored and reported.
    set_int(u, SOL_SOCKET, X_SO_DONTROUTE, 1, "SO_DONTROUTE");
    get_int_expect(u, SOL_SOCKET, X_SO_DONTROUTE, 1, "SO_DONTROUTE");
    set_int(u, SOL_SOCKET, X_SO_OOBINLINE, 1, "SO_OOBINLINE");
    get_int_expect(u, SOL_SOCKET, X_SO_OOBINLINE, 1, "SO_OOBINLINE");
    set_int(u, SOL_SOCKET, X_SO_NO_CHECK, 1, "SO_NO_CHECK");
    get_int_expect(u, SOL_SOCKET, X_SO_NO_CHECK, 1, "SO_NO_CHECK");
    set_int(u, SOL_SOCKET, X_SO_PRIORITY, 6, "SO_PRIORITY 6");
    get_int_expect(u, SOL_SOCKET, X_SO_PRIORITY, 6, "SO_PRIORITY");
    get_int_expect(u, SOL_SOCKET, X_SO_RCVLOWAT, 1, "default SO_RCVLOWAT");
    set_int(u, SOL_SOCKET, X_SO_RCVLOWAT, 0, "SO_RCVLOWAT 0");
    get_int_expect(u, SOL_SOCKET, X_SO_RCVLOWAT, 1, "SO_RCVLOWAT 0 reads 1");
    get_int_expect(u, SOL_SOCKET, X_SO_SNDLOWAT, 1, "SO_SNDLOWAT");
    set_expect(u, SOL_SOCKET, X_SO_SNDLOWAT, &one, sizeof(one), ENOPROTOOPT, "SO_SNDLOWAT set");
    get_int_expect(u, SOL_SOCKET, X_SO_INCOMING_CPU, -1, "default SO_INCOMING_CPU");
    get_int_expect(u, SOL_SOCKET, X_SO_MARK, 0, "default SO_MARK");
    // SO_MARK needs CAP_NET_RAW or CAP_NET_ADMIN.
    set_expect(u, SOL_SOCKET, X_SO_MARK, &one, sizeof(one), geteuid() == 0 ? 0 : EPERM,
               "SO_MARK");
    // SO_PRIORITY outside 0..6 needs CAP_NET_ADMIN/CAP_NET_RAW.
    int seven = 7;
    set_expect(u, SOL_SOCKET, X_SO_PRIORITY, &seven, sizeof(seven), geteuid() == 0 ? 0 : EPERM,
               "SO_PRIORITY 7");
    // SO_BINDTOIFINDEX binds by index and reads back; 0 unbinds.
    set_int(u, SOL_SOCKET, X_SO_BINDTOIFINDEX, 1, "SO_BINDTOIFINDEX 1");
    get_int_expect(u, SOL_SOCKET, X_SO_BINDTOIFINDEX, 1, "SO_BINDTOIFINDEX");
    char dev[16] = {0};
    len = sizeof(dev);
    if (getsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, dev, &len) != 0 || strcmp(dev, "lo") != 0)
        FAIL("SO_BINDTODEVICE after SO_BINDTOIFINDEX(1) = '%s' errno=%d", dev, errno);
    // Linux lets an unprivileged task drop a device binding only with
    // CAP_NET_RAW (sock_bindtoindex_locked); expect that as-is.
    set_expect(u, SOL_SOCKET, X_SO_BINDTOIFINDEX, &zero, sizeof(zero),
               geteuid() == 0 ? 0 : EPERM, "SO_BINDTOIFINDEX 0");
    // sock_bindtoindex_locked never looks the index up: a negative index is
    // EINVAL, an unknown one is stored as-is.
    int fresh = must_socket(AF_INET, SOCK_DGRAM, 0);
    int neg1 = -1, unknown = 0x7fff0;
    set_expect(fresh, SOL_SOCKET, X_SO_BINDTOIFINDEX, &neg1, sizeof(neg1), EINVAL,
               "SO_BINDTOIFINDEX -1");
    set_expect(fresh, SOL_SOCKET, X_SO_BINDTOIFINDEX, &unknown, sizeof(unknown), 0,
               "SO_BINDTOIFINDEX unknown index");
    get_int_expect(fresh, SOL_SOCKET, X_SO_BINDTOIFINDEX, unknown, "SO_BINDTOIFINDEX unknown");
    close(fresh);
    // SO_DETACH_FILTER with no filter → ENOENT.
    set_expect(u, SOL_SOCKET, X_SO_DETACH_FILTER, &zero, sizeof(zero), ENOENT, "SO_DETACH_FILTER");
    // SO_TXREHASH is TCP-only.
    set_expect(u, SOL_SOCKET, X_SO_TXREHASH, &zero, sizeof(zero), EOPNOTSUPP,
               "SO_TXREHASH on UDP");
    get_errno_expect(u, SOL_SOCKET, X_SO_TXREHASH, EOPNOTSUPP, "SO_TXREHASH on UDP");
    // SO_PASSCRED is for AF_UNIX / AF_NETLINK sockets (sk_may_scm_recv).
    set_expect(u, SOL_SOCKET, X_SO_PASSCRED, &one, sizeof(one), EOPNOTSUPP,
               "SO_PASSCRED on AF_INET");
    get_errno_expect(u, SOL_SOCKET, X_SO_PASSCRED, EOPNOTSUPP, "SO_PASSCRED on AF_INET");
    // Read-only options.
    set_expect(u, SOL_SOCKET, SO_TYPE, &one, sizeof(one), ENOPROTOOPT, "SO_TYPE set");
    // Every int SOL_SOCKET option needs optlen >= 4.
    set_expect(u, SOL_SOCKET, X_SO_PRIORITY, &one, 3, EINVAL, "SO_PRIORITY optlen 3");
    // A truly unknown option.
    set_expect(u, SOL_SOCKET, 1999, &one, sizeof(one), ENOPROTOOPT, "SOL_SOCKET 1999");
    get_errno_expect(u, SOL_SOCKET, 1999, ENOPROTOOPT, "SOL_SOCKET 1999");
    close(u);

    int tcp = must_socket(AF_INET, SOCK_STREAM, 0);
    set_int(tcp, SOL_SOCKET, X_SO_TXREHASH, 0, "SO_TXREHASH on TCP");
    get_int_expect(tcp, SOL_SOCKET, X_SO_TXREHASH, 0, "SO_TXREHASH");
    close(tcp);

    int un = must_socket(AF_UNIX, SOCK_STREAM, 0);
    set_int(un, SOL_SOCKET, X_SO_PASSCRED, 1, "SO_PASSCRED on AF_UNIX");
    get_int_expect(un, SOL_SOCKET, X_SO_PASSCRED, 1, "SO_PASSCRED on AF_UNIX");
    // SO_REUSEPORT is inet-only (sk_is_inet).
    set_expect(un, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one), EOPNOTSUPP,
               "SO_REUSEPORT on AF_UNIX");
    set_int(un, SOL_SOCKET, SO_REUSEPORT, 0, "SO_REUSEPORT 0 on AF_UNIX");
    // IP level on AF_UNIX: no proto setsockopt → EOPNOTSUPP.
    set_expect(un, IPPROTO_IP, X_IP_MULTICAST_LOOP, &one, sizeof(one), EOPNOTSUPP,
               "IP level on AF_UNIX");
    v = 0;
    (void)v;
    close(un);
}

// ── IP_MULTICAST_LOOP decides whether a multicast send reaches a local member ──

// Returns 1 when the member socket received this send, 0 when it did not,
// -2 when the host has no multicast route (nothing to test), and a
// distinct negative code for any unexpected failure. The port is 5353 so a
// host firewall that admits mDNS admits the looped copy; the payload is
// unique per run so another mDNS responder's traffic is ignored.
static int mcast_receive(int ifindex, int loop) {
    int rx = must_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    set_int(rx, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");
    bind_any4(rx, 5353);
    // ifindex 0 joins on the default-route interface, the way avahi and
    // resolved join on each configured link.
    struct ip_mreqn m = {.imr_ifindex = ifindex};
    m.imr_multiaddr.s_addr = htonl(0xE00000FB);
    if (setsockopt(rx, IPPROTO_IP, X_IP_ADD_MEMBERSHIP, &m, sizeof(m)) != 0) {
        int e = errno;
        close(rx);
        return e == ENODEV ? -2 : -1000 - e;
    }
    int tx = must_socket(AF_INET, SOCK_DGRAM, 0);
    set_int(tx, IPPROTO_IP, X_IP_MULTICAST_LOOP, loop, "IP_MULTICAST_LOOP");
    set_int(tx, IPPROTO_IP, X_IP_MULTICAST_TTL, 1, "IP_MULTICAST_TTL");
    if (ifindex) {
        struct ip_mreqn out = {.imr_ifindex = ifindex};
        set_expect(tx, IPPROTO_IP, X_IP_MULTICAST_IF, &out, sizeof(out), 0,
                   "IP_MULTICAST_IF ifindex");
    }
    char payload[32];
    int plen = snprintf(payload, sizeof(payload), "sockopt-mcast-%d-%d", (int)getpid(), loop);
    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(5353)};
    dst.sin_addr.s_addr = htonl(0xE00000FB);
    ssize_t w = sendto(tx, payload, plen, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (w != plen) {
        int e = errno;
        close(tx);
        close(rx);
        return e == ENETUNREACH ? -2 : -2000 - e;
    }
    int got = 0;
    long long deadline = now_ms() + (loop ? 2000 : 400);
    while (!got) {
        long long left = deadline - now_ms();
        if (left <= 0)
            break;
        struct pollfd p = {rx, POLLIN, 0};
        if (poll(&p, 1, (int)left) != 1)
            break;
        char b[64];
        ssize_t n = recv(rx, b, sizeof(b), 0);
        if (n == plen && memcmp(b, payload, plen) == 0)
            got = 1;
    }
    close(tx);
    close(rx);
    return got;
}

static void multicast_loop(void) {
    // ip_mc_output: a multicast leaving a real interface is cloned back to
    // local members only while IP_MULTICAST_LOOP is set.
    current = "ip_multicast_loop/default-route-on";
    int r = mcast_receive(0, 1);
    if (r == -2) {
        printf("sockopt-daemon: default-route multicast skipped (no multicast route)\n");
    } else {
        if (r != 1)
            FAIL("a local member did not receive a looped-back multicast (r=%d)", r);
        current = "ip_multicast_loop/default-route-off";
        r = mcast_receive(0, 0);
        if (r != 0)
            FAIL("IP_MULTICAST_LOOP=0 still delivered locally (r=%d)", r);
        printf("sockopt-daemon: default-route multicast loop on/off verified\n");
    }
    // Over the loopback device the packet itself comes back in through lo
    // (the lo route's output is plain ip_output, not ip_mc_output), so a
    // member on lo receives it whatever IP_MULTICAST_LOOP says.
    current = "ip_multicast_loop/lo-on";
    r = mcast_receive(1, 1);
    if (r != 1)
        FAIL("a member on lo did not receive a multicast sent out lo (r=%d)", r);
    current = "ip_multicast_loop/lo-off";
    r = mcast_receive(1, 0);
    if (r != 1)
        FAIL("a member on lo missed a multicast sent out lo with loop off (r=%d)", r);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    resolved_llmnr_ipv4_udp();
    resolved_llmnr_ipv6_udp();
    resolved_llmnr_tcp();
    resolved_mdns();
    resolved_dns_scope();
    avahi_ipv4();
    avahi_ipv6();
    userdbd_listener_timeout();
    timeout_contract();
    ip_contract();
    ipv6_contract();
    sol_socket_contract();
    multicast_loop();
    printf("sockopt-daemon-ok\n");
    return 0;
}
