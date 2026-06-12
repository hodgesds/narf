// eventfd(2) smoke. Exercises the eventfd2 syscall end-to-end via a
// real musl binary: create a counter eventfd, write a value, read it
// back, and verify the counter semantics. Success token "eventfd-ok".
//
// Build: see REGEN_eventfd_smoke.sh (musl-gcc, static-PIE).
#include <sys/eventfd.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = eventfd(0, 0);
    if (fd < 0) {
        w("eventfd-fail: create\n");
        return 1;
    }
    // Add 5 to the counter, then read it back. A non-semaphore
    // eventfd read returns the whole counter and resets it to 0.
    uint64_t v = 5;
    if (write(fd, &v, sizeof v) != (ssize_t)sizeof v) {
        w("eventfd-fail: write\n");
        return 1;
    }
    uint64_t r = 0;
    if (read(fd, &r, sizeof r) != (ssize_t)sizeof r) {
        w("eventfd-fail: read\n");
        return 1;
    }
    if (r == 5) {
        w("eventfd-ok\n");
    } else {
        w("eventfd-fail: value\n");
    }
    close(fd);
    return 0;
}
