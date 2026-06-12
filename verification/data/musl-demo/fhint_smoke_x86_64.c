// readahead(2) / sync_file_range(2) smoke. Both are page-cache / writeback
// hints that NARF's in-memory FSes accept as no-ops for a valid fd. Open a
// file, issue both against it, and confirm they succeed; then confirm a
// bogus fd is rejected with EBADF. Success token "fhint-ok".
//
// Build: see REGEN_fhint_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    const char *path = "/dev/shm/fhint_target";
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) { w("fhint-fail: open\n"); return 1; }
    if (write(fd, "payload", 7) != 7) { w("fhint-fail: write\n"); return 1; }

    if (readahead(fd, 0, 4096) != 0) { w("fhint-fail: readahead\n"); return 1; }

    // SYNC_FILE_RANGE_WAIT_BEFORE|WRITE|WAIT_AFTER == 7
    if (sync_file_range(fd, 0, 7, 7) != 0) { w("fhint-fail: sync_file_range\n"); return 1; }

    // A bogus fd must fail with EBADF.
    errno = 0;
    if (readahead(999, 0, 4096) != -1 || errno != EBADF) {
        w("fhint-fail: readahead-badfd\n"); return 1;
    }
    errno = 0;
    if (sync_file_range(999, 0, 1, 7) != -1 || errno != EBADF) {
        w("fhint-fail: sync-badfd\n"); return 1;
    }

    close(fd);
    w("fhint-ok\n");
    return 0;
}
