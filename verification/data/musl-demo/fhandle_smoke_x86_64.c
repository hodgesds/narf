// File-handle smoke: name_to_handle_at + open_by_handle_at round-trip.
// Encode a file into an opaque handle, then re-open it by handle and read
// the contents back; also check the too-small-buffer EOVERFLOW path and
// that a corrupted handle type is rejected with ESTALE. Issued raw (struct
// + numbers defined locally) so it builds on older CI musl. Token
// "fhandle-ok".
//
// Build: see REGEN_fhandle_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef SYS_name_to_handle_at
#define SYS_name_to_handle_at 303
#endif
#ifndef SYS_open_by_handle_at
#define SYS_open_by_handle_at 304
#endif

#define ATFD (-100) /* AT_FDCWD */

struct fh {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[128];
};

static void w(const char *m) { write(1, m, strlen(m)); }

#define PATH "/dev/shm/fh_target"
#define DATA "handle-data"

int main(void) {
    // Create + populate the target.
    int fd = open(PATH, O_CREAT | O_RDWR, 0600);
    if (fd < 0) { w("fhandle-fail: create\n"); return 1; }
    if (write(fd, DATA, strlen(DATA)) != (ssize_t)strlen(DATA)) { w("fhandle-fail: write\n"); return 1; }
    close(fd);

    // Encode the file into a handle.
    struct fh h;
    h.handle_bytes = sizeof h.f_handle;
    int mount_id = -1;
    if (syscall(SYS_name_to_handle_at, (long)ATFD, PATH, &h, &mount_id, 0L) != 0) {
        w("fhandle-fail: n2h\n"); return 1;
    }
    if (h.handle_bytes == 0 || h.handle_bytes > sizeof h.f_handle) { w("fhandle-fail: bytes\n"); return 1; }

    // Re-open by handle and read the data back.
    int hfd = syscall(SYS_open_by_handle_at, (long)ATFD, &h, (long)O_RDONLY);
    if (hfd < 0) { w("fhandle-fail: obh\n"); return 1; }
    char buf[64];
    ssize_t n = read(hfd, buf, sizeof buf);
    close(hfd);
    if (n < (ssize_t)strlen(DATA) || memcmp(buf, DATA, strlen(DATA)) != 0) {
        w("fhandle-fail: content\n"); return 1;
    }

    // Too-small buffer reports EOVERFLOW and the required size.
    struct fh small;
    small.handle_bytes = 1;
    if (syscall(SYS_name_to_handle_at, (long)ATFD, PATH, &small, &mount_id, 0L) != -1
        || errno != EOVERFLOW) {
        w("fhandle-fail: overflow\n"); return 1;
    }
    if (small.handle_bytes != h.handle_bytes) { w("fhandle-fail: overflow-size\n"); return 1; }

    // A foreign/corrupt handle type is rejected with ESTALE.
    struct fh bad = h;
    bad.handle_type ^= 0x1234;
    if (syscall(SYS_open_by_handle_at, (long)ATFD, &bad, (long)O_RDONLY) != -1
        || errno != ESTALE) {
        w("fhandle-fail: stale\n"); return 1;
    }

    unlink(PATH);
    w("fhandle-ok\n");
    return 0;
}
