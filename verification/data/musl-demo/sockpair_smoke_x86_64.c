// socketpair(2) smoke. Exercises the socketpair syscall end-to-end
// via a real musl binary: create a connected AF_UNIX SOCK_STREAM pair,
// round-trip bytes in both directions across the pair. The pair is
// pre-connected, so no listener/accept handshake (and no second
// thread) is needed. Success token "sockpair-ok".
//
// Build: see REGEN_sockpair_smoke.sh (musl-gcc, static-PIE).
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        w("sockpair-fail: create\n");
        return 1;
    }

    // Direction 1: sv[0] -> sv[1].
    if (write(sv[0], "ping", 4) != 4) {
        w("sockpair-fail: write0\n");
        return 1;
    }
    char b[8] = {0};
    if (read(sv[1], b, sizeof b) != 4 || memcmp(b, "ping", 4) != 0) {
        w("sockpair-fail: read1\n");
        return 1;
    }

    // Direction 2: sv[1] -> sv[0].
    if (write(sv[1], "pong", 4) != 4) {
        w("sockpair-fail: write1\n");
        return 1;
    }
    memset(b, 0, sizeof b);
    if (read(sv[0], b, sizeof b) != 4 || memcmp(b, "pong", 4) != 0) {
        w("sockpair-fail: read0\n");
        return 1;
    }

    w("sockpair-ok\n");
    close(sv[0]);
    close(sv[1]);
    return 0;
}
