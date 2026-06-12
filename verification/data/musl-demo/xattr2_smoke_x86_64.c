// xattr l*/f*/remove variants smoke. Exercises the symlink-nofollow
// (l*) aliases, the fd-based (f*) family, and the remove paths. Success
// token "xattr2-ok".
//
// Build: see REGEN_xattr2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/xattr.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    const char *path = "/dev/shm/xattr2_target";
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) { w("xattr2-fail: open\n"); return 1; }

    // ── l* variants (alias the path family; no symlink to follow here) ──
    if (lsetxattr(path, "user.l", "lval", 4, 0) != 0) { w("xattr2-fail: lsetxattr\n"); return 1; }
    char buf[32];
    memset(buf, 0, sizeof buf);
    ssize_t n = lgetxattr(path, "user.l", buf, sizeof buf);
    if (n != 4 || memcmp(buf, "lval", 4) != 0) { w("xattr2-fail: lgetxattr\n"); return 1; }
    // path-keyed getxattr sees the l-set value (l* aliases path family).
    memset(buf, 0, sizeof buf);
    if (getxattr(path, "user.l", buf, sizeof buf) != 4 || memcmp(buf, "lval", 4) != 0) {
        w("xattr2-fail: l-path-share\n"); return 1;
    }
    char list[64];
    memset(list, 0, sizeof list);
    if (llistxattr(path, list, sizeof list) <= 0) { w("xattr2-fail: llistxattr\n"); return 1; }

    // ── remove ──
    if (removexattr(path, "user.l") != 0) { w("xattr2-fail: removexattr\n"); return 1; }
    if (getxattr(path, "user.l", buf, sizeof buf) != -1) { w("xattr2-fail: still-present\n"); return 1; }

    // ── f* variants (self-consistent on the same fd) ──
    if (fsetxattr(fd, "user.f", "fval", 4, 0) != 0) { w("xattr2-fail: fsetxattr\n"); return 1; }
    memset(buf, 0, sizeof buf);
    n = fgetxattr(fd, "user.f", buf, sizeof buf);
    if (n != 4 || memcmp(buf, "fval", 4) != 0) { w("xattr2-fail: fgetxattr\n"); return 1; }
    memset(list, 0, sizeof list);
    if (flistxattr(fd, list, sizeof list) <= 0) { w("xattr2-fail: flistxattr\n"); return 1; }
    if (fremovexattr(fd, "user.f") != 0) { w("xattr2-fail: fremovexattr\n"); return 1; }
    if (fgetxattr(fd, "user.f", buf, sizeof buf) != -1) { w("xattr2-fail: f-still-present\n"); return 1; }

    close(fd);
    w("xattr2-ok\n");
    return 0;
}
