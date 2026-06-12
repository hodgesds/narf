// setxattr(2) / getxattr(2) / listxattr(2) smoke. Create a file, attach
// a user.* extended attribute, read it back (both the size-probe and the
// copy paths), and confirm the name shows up in listxattr. Success token
// "xattr-ok".
//
// Build: see REGEN_xattr_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/xattr.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    const char *path = "/dev/shm/xattr_target";
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) { w("xattr-fail: open\n"); return 1; }
    close(fd);

    const char *name = "user.narf";
    const char *val = "hello-xattr";
    size_t vlen = strlen(val);
    if (setxattr(path, name, val, vlen, 0) != 0) { w("xattr-fail: setxattr\n"); return 1; }

    // Size-probe: value == NULL, size == 0 returns the length.
    ssize_t need = getxattr(path, name, 0, 0);
    if (need != (ssize_t)vlen) { w("xattr-fail: getxattr-size\n"); return 1; }

    char buf[64];
    memset(buf, 0, sizeof buf);
    ssize_t got = getxattr(path, name, buf, sizeof buf);
    if (got != (ssize_t)vlen || memcmp(buf, val, vlen) != 0) {
        w("xattr-fail: getxattr-value\n"); return 1;
    }

    // listxattr should contain the NUL-terminated name.
    char list[128];
    memset(list, 0, sizeof list);
    ssize_t llen = listxattr(path, list, sizeof list);
    if (llen <= 0) { w("xattr-fail: listxattr\n"); return 1; }
    int found = 0;
    for (ssize_t off = 0; off < llen; off += (ssize_t)strlen(list + off) + 1) {
        if (strcmp(list + off, name) == 0) { found = 1; break; }
    }
    if (!found) { w("xattr-fail: list-missing\n"); return 1; }

    w("xattr-ok\n");
    return 0;
}
