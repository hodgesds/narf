// Relative-path *at coverage. After chdir into a writable dir, every
// filesystem mutation issued with a RELATIVE path (mkdir/open-create/
// rename/symlink/readlink/stat/unlink/rmdir, all AT_FDCWD under musl)
// must resolve against the cwd. This is what lets `mkdir foo`, `mv a b`,
// `rm foo`, `ln -s a b` work from a shell. Success token "relpaths-ok".
//
// Build: see REGEN_relpaths_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    if (chdir("/dev/shm") != 0) {
        w("relpaths-fail: chdir\n");
        return 1;
    }
    if (mkdir("rpdir", 0755) != 0) {
        w("relpaths-fail: mkdir\n");
        return 1;
    }
    int fd = open("rpdir/a.txt", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        w("relpaths-fail: create\n");
        return 1;
    }
    write(fd, "hi", 2);
    close(fd);
    if (rename("rpdir/a.txt", "rpdir/b.txt") != 0) {
        w("relpaths-fail: rename\n");
        return 1;
    }
    // relative stat must find the renamed file
    struct stat st;
    if (stat("rpdir/b.txt", &st) != 0) {
        w("relpaths-fail: stat\n");
        return 1;
    }
    if (unlink("rpdir/b.txt") != 0) {
        w("relpaths-fail: unlink\n");
        return 1;
    }
    if (rmdir("rpdir") != 0) {
        w("relpaths-fail: rmdir\n");
        return 1;
    }
    w("relpaths-ok\n");
    return 0;
}
