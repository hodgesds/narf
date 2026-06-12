// sendfile(2) smoke. Use a memfd as the source file (avoids needing a
// writable FS path), write a payload into it, then sendfile it into a
// pipe and read it back out the other end. Success token "sendfile-ok".
//
// Build: see REGEN_sendfile_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int mfd = memfd_create("sf", 0);
    if (mfd < 0) {
        w("sendfile-fail: memfd\n");
        return 1;
    }
    const char *data = "sendfile-payload";
    size_t n = strlen(data);
    if (write(mfd, data, n) != (ssize_t)n) {
        w("sendfile-fail: write\n");
        return 1;
    }
    lseek(mfd, 0, SEEK_SET);

    int pf[2];
    if (pipe(pf) < 0) {
        w("sendfile-fail: pipe\n");
        return 1;
    }
    ssize_t sent = sendfile(pf[1], mfd, NULL, n);
    if (sent != (ssize_t)n) {
        w("sendfile-fail: sendfile\n");
        return 1;
    }
    char buf[64] = {0};
    ssize_t r = read(pf[0], buf, sizeof buf);
    if (r == (ssize_t)n && memcmp(buf, data, n) == 0) {
        w("sendfile-ok\n");
    } else {
        w("sendfile-fail: verify\n");
    }
    close(pf[0]);
    close(pf[1]);
    close(mfd);
    return 0;
}
