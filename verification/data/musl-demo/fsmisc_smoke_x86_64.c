// Filesystem-misc smoke (legacy x86_64 entries): creat, lchown, utime,
// utimes. Success token "fsmisc-ok".
//
// Build: see REGEN_fsmisc_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/time.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    const char *path = "/dev/shm/fsmisc_target";

    // creat == open(O_CREAT|O_WRONLY|O_TRUNC): returns a writable fd.
    int fd = creat(path, 0644);
    if (fd < 0) { w("fsmisc-fail: creat\n"); return 1; }
    if (write(fd, "creat-data", 10) != 10) { w("fsmisc-fail: write\n"); return 1; }
    close(fd);

    // Read it back through a fresh open.
    int rfd = open(path, O_RDONLY);
    if (rfd < 0) { w("fsmisc-fail: reopen\n"); return 1; }
    char buf[16];
    memset(buf, 0, sizeof buf);
    if (read(rfd, buf, sizeof buf) != 10 || memcmp(buf, "creat-data", 10) != 0) {
        w("fsmisc-fail: readback\n"); return 1;
    }
    close(rfd);

    // lchown with -1/-1 is a no-op ownership change (no privilege needed).
    if (lchown(path, (uid_t)-1, (gid_t)-1) != 0) { w("fsmisc-fail: lchown\n"); return 1; }

    // utime / utimes set times to now (NULL).
    if (utime(path, NULL) != 0) { w("fsmisc-fail: utime\n"); return 1; }
    if (utimes(path, NULL) != 0) { w("fsmisc-fail: utimes\n"); return 1; }

    w("fsmisc-ok\n");
    return 0;
}
