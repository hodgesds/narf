// dup3(2) + fadvise64(2) + mlock2(2) smoke. dup3 with O_CLOEXEC must
// set FD_CLOEXEC on the new fd; fadvise64 and mlock2 are accepted.
// Success token "dup3-ok".
//
// Build: see REGEN_dup3fam_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // dup3 stdout to fd 7 with O_CLOEXEC.
    if (dup3(1, 7, O_CLOEXEC) != 7) {
        w("dup3-fail: dup3\n");
        return 1;
    }
    int fl = fcntl(7, F_GETFD);
    if (fl < 0 || !(fl & FD_CLOEXEC)) {
        w("dup3-fail: cloexec\n");
        return 1;
    }
    close(7);

    // fadvise64 on a valid fd.
    if (posix_fadvise(1, 0, 0, POSIX_FADV_NORMAL) != 0) {
        w("dup3-fail: fadvise\n");
        return 1;
    }

    // mlock2 an anonymous page.
    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        w("dup3-fail: mmap\n");
        return 1;
    }
    if (syscall(SYS_mlock2, p, 4096, 0) != 0) {
        w("dup3-fail: mlock2\n");
        return 1;
    }

    w("dup3-ok\n");
    munmap(p, 4096);
    return 0;
}
