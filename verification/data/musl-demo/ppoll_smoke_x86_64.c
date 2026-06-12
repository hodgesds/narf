// ppoll(2) smoke. Write a byte into a pipe, then ppoll the read end
// with a timespec timeout and verify POLLIN comes back. Success token
// "ppoll-ok".
//
// Build: see REGEN_ppoll_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int pf[2];
    if (pipe(pf) < 0) {
        w("ppoll-fail: pipe\n");
        return 1;
    }
    if (write(pf[1], "x", 1) != 1) {
        w("ppoll-fail: write\n");
        return 1;
    }
    struct pollfd p = {.fd = pf[0], .events = POLLIN, .revents = 0};
    struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
    int n = ppoll(&p, 1, &ts, NULL);
    if (n >= 1 && (p.revents & POLLIN)) {
        w("ppoll-ok\n");
    } else {
        w("ppoll-fail: revents\n");
    }
    close(pf[0]);
    close(pf[1]);
    return 0;
}
