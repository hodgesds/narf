// Filesystem-navigation smoke. Exercises the directory-fd path that a
// real Linux shell relies on: chdir into /bin, confirm getcwd reflects
// it, then opendir(".") + readdir() (which musl implements as
// open(".", O_DIRECTORY) + getdents64 on the fd) and confirm we can
// enumerate the directory and find the seeded `busybox` entry. This is
// what makes `cd` + `ls` work under busybox sh. Success token
// "navfs-ok".
//
// Build: see REGEN_navfs_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <dirent.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // chdir takes a NUL-terminated path (no length arg) — the Linux ABI.
    if (chdir("/bin") != 0) {
        w("navfs-fail: chdir\n");
        return 1;
    }
    char cwd[64];
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/bin") != 0) {
        w("navfs-fail: getcwd\n");
        return 1;
    }
    // opendir(".") resolves "." against the cwd, opens a directory fd,
    // and readdir() pulls entries via getdents64 on that fd.
    DIR *d = opendir(".");
    if (!d) {
        w("navfs-fail: opendir\n");
        return 1;
    }
    int count = 0, found = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        count++;
        if (strcmp(e->d_name, "busybox") == 0) {
            found = 1;
        }
    }
    closedir(d);
    if (count < 1) {
        w("navfs-fail: empty\n");
        return 1;
    }
    if (!found) {
        w("navfs-fail: no-busybox\n");
        return 1;
    }
    w("navfs-ok\n");
    return 0;
}
