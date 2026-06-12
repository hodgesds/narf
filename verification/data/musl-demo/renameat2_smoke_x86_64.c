// renameat2(2) smoke. Exercises RENAME_NOREPLACE: renaming to a
// non-existent name succeeds, renaming over an existing name fails
// with EEXIST. Uses /dev/shm (writable tmpfs) and the raw syscall()
// form. Success token "renameat2-ok".
//
// Build: see REGEN_renameat2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define A "/dev/shm/rnt2_a"
#define B "/dev/shm/rnt2_b"
#define C "/dev/shm/rnt2_c"
#define RENAME_NOREPLACE 1

int main(void) {
    int fa = open(A, O_CREAT | O_RDWR, 0644);
    if (fa < 0) {
        w("renameat2-fail: open-a\n");
        return 1;
    }
    close(fa);
    int fc = open(C, O_CREAT | O_RDWR, 0644);
    if (fc < 0) {
        w("renameat2-fail: open-c\n");
        return 1;
    }
    close(fc);

    // A -> B with NOREPLACE: B does not exist, so this succeeds.
    if (syscall(SYS_renameat2, AT_FDCWD, A, AT_FDCWD, B, RENAME_NOREPLACE) != 0) {
        w("renameat2-fail: noreplace-new\n");
        return 1;
    }
    // B -> C with NOREPLACE: C exists, so this must fail (EEXIST).
    long r = syscall(SYS_renameat2, AT_FDCWD, B, AT_FDCWD, C, RENAME_NOREPLACE);
    if (r == 0) {
        w("renameat2-fail: noreplace-overwrote\n");
        return 1;
    }

    w("renameat2-ok\n");
    return 0;
}
