// Off-box network serving smoke. The guest half of the "real server
// reachable from outside the VM" test: bind 0.0.0.0:7777, accept ONE
// TCP connection from an external client (the host, routed in by QEMU
// user-mode `hostfwd`), echo back the line it sends, and exit. This
// exercises the full server path — socket/bind/listen/accept/read/write
// over the virtio-net iface to a genuine off-box peer, not loopback.
//
// Tokens on the serial console:
//   * "netserve: listening" — emitted after listen(), BEFORE accept().
//     The host-side harness waits for this before opening its socket.
//   * "netserve-ok"         — after a successful echo round-trip.
//
// Build: the uniform musl-demo recipe (musl-gcc -O2 -fPIE -pie).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
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
    w("netserve-ok\n");
    return 0;
}
