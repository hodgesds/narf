// New mount API smoke: build and attach a tmpfs the modern way, then prove
// it's live. fsopen -> fsconfig(CMD_CREATE) -> fsmount -> move_mount onto
// /mnt/newfs, then create + read a file inside it. Also exercise open_tree
// (clone the mount), fspick (context for an existing mount), and
// mount_setattr. Issued raw (no musl wrappers). Token "mountapi-ok".
//
// Build: see REGEN_mountapi_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>

#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_fsopen
#define SYS_fsopen 430
#endif
#ifndef SYS_fsconfig
#define SYS_fsconfig 431
#endif
#ifndef SYS_fsmount
#define SYS_fsmount 432
#endif
#ifndef SYS_fspick
#define SYS_fspick 433
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

#define ATFD (-100) /* AT_FDCWD */
#define FSCONFIG_CMD_CREATE 6
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define OPEN_TREE_CLONE 1

struct mount_attr {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

static void w(const char *m) { write(1, m, strlen(m)); }

#define MNT "/mnt/newfs"
#define FILE MNT "/hello"
#define DATA "mounted-data"

int main(void) {
    // fsopen tmpfs → fsconfig(CMD_CREATE) → fsmount.
    long fsfd = syscall(SYS_fsopen, "tmpfs", 0L);
    if (fsfd < 0) { w("mountapi-fail: fsopen\n"); return 1; }
    if (syscall(SYS_fsconfig, fsfd, (long)FSCONFIG_CMD_CREATE, (void *)0, (void *)0, 0L) != 0) {
        w("mountapi-fail: fsconfig\n"); return 1;
    }
    long mfd = syscall(SYS_fsmount, fsfd, 0L, 0L);
    if (mfd < 0) { w("mountapi-fail: fsmount\n"); return 1; }

    // Attach the detached mount at /mnt/newfs.
    if (syscall(SYS_move_mount, mfd, "", (long)ATFD, MNT, (long)MOVE_MOUNT_F_EMPTY_PATH) != 0) {
        w("mountapi-fail: move_mount\n"); return 1;
    }

    // The new tmpfs must be live: create a file, read it back.
    int fd = open(FILE, O_CREAT | O_RDWR, 0600);
    if (fd < 0) { w("mountapi-fail: open\n"); return 1; }
    if (write(fd, DATA, strlen(DATA)) != (ssize_t)strlen(DATA)) { w("mountapi-fail: write\n"); return 1; }
    close(fd);
    fd = open(FILE, O_RDONLY);
    if (fd < 0) { w("mountapi-fail: reopen\n"); return 1; }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    if (n != (ssize_t)strlen(DATA) || memcmp(buf, DATA, strlen(DATA)) != 0) {
        w("mountapi-fail: content\n"); return 1;
    }

    // open_tree clones the mount; fspick opens a reconfig context.
    long tfd = syscall(SYS_open_tree, (long)ATFD, MNT, (long)OPEN_TREE_CLONE);
    if (tfd < 0) { w("mountapi-fail: open_tree\n"); return 1; }
    close((int)tfd);
    long pfd = syscall(SYS_fspick, (long)ATFD, MNT, 0L);
    if (pfd < 0) { w("mountapi-fail: fspick\n"); return 1; }
    close((int)pfd);

    // mount_setattr accepts a well-formed request.
    struct mount_attr ma;
    memset(&ma, 0, sizeof ma);
    if (syscall(SYS_mount_setattr, (long)ATFD, MNT, 0L, &ma, (long)sizeof ma) != 0) {
        w("mountapi-fail: setattr\n"); return 1;
    }

    close((int)mfd);
    close((int)fsfd);
    w("mountapi-ok\n");
    return 0;
}
