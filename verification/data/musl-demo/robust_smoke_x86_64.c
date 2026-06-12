// set_robust_list(2) / get_robust_list(2) smoke. Register a robust
// futex list head and read it back, verifying the pointer + length
// round-trip. Raw syscall() form (musl has no public wrappers).
// Success token "robust-ok".
//
// Build: see REGEN_robust_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    void *head = (void *)0x1234abcd0000UL;
    unsigned long len = 24;
    if (syscall(SYS_set_robust_list, head, len) != 0) {
        w("robust-fail: set\n");
        return 1;
    }
    void *got_head = NULL;
    unsigned long got_len = 0;
    if (syscall(SYS_get_robust_list, 0, &got_head, &got_len) != 0) {
        w("robust-fail: get\n");
        return 1;
    }
    if (got_head == head && got_len == len) {
        w("robust-ok\n");
    } else {
        w("robust-fail: mismatch\n");
    }
    return 0;
}
