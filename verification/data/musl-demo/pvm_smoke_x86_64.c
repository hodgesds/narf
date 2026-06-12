// process_vm_readv / process_vm_writev smoke. Both target the calling
// process (a valid Linux self-copy), exercising the iovec gather/scatter
// machinery: readv copies a source buffer into a destination buffer, and
// writev does the reverse direction. Success token "pvm-ok".
//
// Build: see REGEN_pvm_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    pid_t self = getpid();

    char src[32];
    memcpy(src, "process-vm-payload!!", 20);
    char dst[32];
    memset(dst, 0, sizeof dst);

    struct iovec local = { dst, 20 };
    struct iovec remote = { src, 20 };
    ssize_t n = process_vm_readv(self, &local, 1, &remote, 1, 0);
    if (n != 20 || memcmp(dst, src, 20) != 0) { w("pvm-fail: readv\n"); return 1; }

    char a[16];
    memcpy(a, "writev-test-ok!", 15);
    char b[16];
    memset(b, 0, sizeof b);
    struct iovec lw = { a, 15 };
    struct iovec rw = { b, 15 };
    n = process_vm_writev(self, &lw, 1, &rw, 1, 0);
    if (n != 15 || memcmp(b, a, 15) != 0) { w("pvm-fail: writev\n"); return 1; }

    // Split across two destination segments to exercise scatter.
    char whole[24];
    memcpy(whole, "twentyfour-byte-payload!", 24);
    char p1[12];
    char p2[12];
    memset(p1, 0, sizeof p1);
    memset(p2, 0, sizeof p2);
    struct iovec src1 = { whole, 24 };
    struct iovec d2[2] = { { p1, 12 }, { p2, 12 } };
    n = process_vm_readv(self, d2, 2, &src1, 1, 0);
    if (n != 24 || memcmp(p1, whole, 12) != 0 || memcmp(p2, whole + 12, 12) != 0) {
        w("pvm-fail: scatter\n"); return 1;
    }

    w("pvm-ok\n");
    return 0;
}
