// Vectored & extended I/O smoke: readv, preadv2/pwritev2 (raw — exact
// offset packing), and tee + vmsplice across a pair of pipes. Success
// token "vio-ok".
//
// Build: see REGEN_vio_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // ── readv: scatter a file read across two buffers ──
    int fd = open("/dev/shm/vio_target", O_CREAT | O_RDWR, 0644);
    if (fd < 0) { w("vio-fail: open\n"); return 1; }
    if (write(fd, "0123456789", 10) != 10) { w("vio-fail: write\n"); return 1; }
    if (lseek(fd, 0, SEEK_SET) != 0) { w("vio-fail: lseek\n"); return 1; }

    char a[4], b[6];
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    struct iovec rv[2] = { { a, 4 }, { b, 6 } };
    if (readv(fd, rv, 2) != 10) { w("vio-fail: readv\n"); return 1; }
    if (memcmp(a, "0123", 4) != 0 || memcmp(b, "456789", 6) != 0) {
        w("vio-fail: readv-data\n"); return 1;
    }

    // ── pwritev2 / preadv2 at an explicit offset ──
    char w1[3] = { 'A', 'B', 'C' };
    char w2[3] = { 'D', 'E', 'F' };
    struct iovec wv[2] = { { w1, 3 }, { w2, 3 } };
    if (syscall(SYS_pwritev2, fd, wv, 2, (long)2, 0L, 0) != 6) {
        w("vio-fail: pwritev2\n"); return 1;
    }
    char rb[6];
    memset(rb, 0, sizeof rb);
    struct iovec rv2[1] = { { rb, 6 } };
    if (syscall(SYS_preadv2, fd, rv2, 1, (long)2, 0L, 0) != 6) {
        w("vio-fail: preadv2\n"); return 1;
    }
    if (memcmp(rb, "ABCDEF", 6) != 0) { w("vio-fail: preadv2-data\n"); return 1; }
    close(fd);

    // ── vmsplice into a pipe, tee it to a second pipe ──
    int p1[2], p2[2];
    if (pipe(p1) != 0 || pipe(p2) != 0) { w("vio-fail: pipe\n"); return 1; }

    char msg[] = "teedata";
    struct iovec vs = { msg, 7 };
    if (vmsplice(p1[1], &vs, 1, 0) != 7) { w("vio-fail: vmsplice\n"); return 1; }

    // Duplicate p1 -> p2 without consuming p1.
    if (tee(p1[0], p2[1], 7, 0) != 7) { w("vio-fail: tee\n"); return 1; }

    char c2[7];
    memset(c2, 0, sizeof c2);
    if (read(p2[0], c2, 7) != 7 || memcmp(c2, "teedata", 7) != 0) {
        w("vio-fail: tee-copy\n"); return 1;
    }
    // The original is still readable (tee did not consume it).
    char c1[7];
    memset(c1, 0, sizeof c1);
    if (read(p1[0], c1, 7) != 7 || memcmp(c1, "teedata", 7) != 0) {
        w("vio-fail: tee-source\n"); return 1;
    }

    w("vio-ok\n");
    return 0;
}
