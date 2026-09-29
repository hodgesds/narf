// `mount -o remount` the way systemd-remount-fs runs it, twice over.
//
// util-linux 2.39+ (libmount) remounts through the new mount API — strace of
// `mount -o remount,noatime <mnt>` on Linux 7.2 / util-linux 2.42:
//
//   open_tree(AT_FDCWD, "<mnt>", OPEN_TREE_CLOEXEC)            = 3
//   fspick(3, "", FSPICK_NO_AUTOMOUNT|FSPICK_EMPTY_PATH)       = 4
//   xfsconfig(4, FSCONFIG_SET_FLAG, "rw", NULL, 0)              = 0
//   xfsconfig(4, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0)       = 0
//   mount_setattr(3, "", AT_EMPTY_PATH,
//                 {attr_set=NOATIME, attr_clr=__ATIME}, 32)    = 0
//
// and older tools through mount(2) MS_REMOUNT. On NARF the reconfigure step
// handed "rw" to the filesystem as one of its own parameters: -EINVAL, which
// util-linux reports as "mount point not mounted or bad option", so
// systemd-remount-fs failed every boot. The flags must also be APPLIED and
// visible in /proc/self/mountinfo: the mount-options column carries the
// attachment's flags (ro/rw, nosuid, nodev, noexec, noatime, relatime), the
// super-options column the superblock's ro/rw.
//
// Needs CAP_SYS_ADMIN over its mount namespace: root on NARF, or
// `unshare -rm` on a Linux host. Success token "remount-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_fspick
#define SYS_fspick 433
#endif
#ifndef SYS_fsconfig
#define SYS_fsconfig 431
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

#define X_FSCONFIG_SET_FLAG 0
#define X_FSCONFIG_SET_STRING 1
#define X_FSCONFIG_CMD_RECONFIGURE 7
#define X_FSPICK_NO_AUTOMOUNT 0x4
#define X_FSPICK_EMPTY_PATH 0x8
#define X_OPEN_TREE_CLOEXEC O_CLOEXEC
#define X_AT_EMPTY_PATH 0x1000
#define X_MOUNT_ATTR_NOATIME 0x10
#define X_MOUNT_ATTR__ATIME 0x70
#define X_MS_STRICTATIME (1 << 24)

struct x_mount_attr {
    uint64_t attr_set, attr_clr, propagation, userns_fd;
};

static const char *mnt = "/tmp/remount-smoke";
static int failures;

static void bad(const char *what, int err) {
    printf("remount-fail: %s (errno %d %s)\n", what, err, strerror(err));
    failures++;
}

// Mount-options (field 6) and super-options first token (after " - "
// fstype source) of mnt's LAST mountinfo line.
static int opts(char *mo, size_t mo_len, char *so, size_t so_len) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    char line[1024];
    int found = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        char point[512], mopts[256], rest[512];
        if (sscanf(line, "%*s %*s %*s %*s %511s %255s%511[^\n]", point, mopts, rest) != 3)
            continue;
        if (strcmp(point, mnt) != 0)
            continue;
        char *dash = strstr(rest, " - ");
        if (!dash)
            continue;
        char fstype[64], src[256], sopts[256];
        if (sscanf(dash + 3, "%63s %255s %255s", fstype, src, sopts) != 3)
            continue;
        char *comma = strchr(sopts, ',');
        if (comma)
            *comma = 0;
        snprintf(mo, mo_len, "%s", mopts);
        snprintf(so, so_len, "%s", sopts);
        found = 1;
    }
    fclose(f);
    return found;
}

static void expect(const char *step, const char *want_mo, const char *want_so) {
    char mo[256] = "", so[256] = "";
    if (!opts(mo, sizeof mo, so, sizeof so)) {
        printf("remount-fail: %s: %s missing from mountinfo\n", step, mnt);
        failures++;
        return;
    }
    if (strcmp(mo, want_mo) != 0 || strcmp(so, want_so) != 0) {
        printf("remount-fail: %s: mountinfo `%s` / `%s`, want `%s` / `%s`\n", step, mo, so,
               want_mo, want_so);
        failures++;
    }
}

static int writable(void) {
    char p[256];
    snprintf(p, sizeof p, "%s/probe", mnt);
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return -errno;
    close(fd);
    unlink(p);
    return 0;
}

static long xfsconfig(int fd, unsigned cmd, const char *key, const char *value) {
    return syscall(SYS_fsconfig, fd, cmd, key, value, 0);
}

int main(void) {
    mkdir(mnt, 0755);
    if (mount("tmpfs", mnt, "tmpfs", 0, "mode=0755") != 0) {
        bad("mount tmpfs fixture", errno);
        return 1;
    }
    expect("fresh mount", "rw,relatime", "rw");

    // ── libmount's new-API remount ──────────────────────────────────
    int tree = syscall(SYS_open_tree, AT_FDCWD, mnt, X_OPEN_TREE_CLOEXEC);
    if (tree < 0)
        bad("open_tree(mnt, OPEN_TREE_CLOEXEC)", errno);
    int fs = syscall(SYS_fspick, tree, "", X_FSPICK_NO_AUTOMOUNT | X_FSPICK_EMPTY_PATH);
    if (fs < 0)
        bad("fspick(tree, \"\", EMPTY_PATH)", errno);
    if (xfsconfig(fs, X_FSCONFIG_SET_FLAG, "rw", NULL) != 0)
        bad("fsconfig(SET_FLAG rw)", errno);
    if (xfsconfig(fs, X_FSCONFIG_CMD_RECONFIGURE, NULL, NULL) != 0)
        bad("fsconfig(CMD_RECONFIGURE) after rw", errno);
    struct x_mount_attr attr = {.attr_set = X_MOUNT_ATTR_NOATIME, .attr_clr = X_MOUNT_ATTR__ATIME};
    if (syscall(SYS_mount_setattr, tree, "", X_AT_EMPTY_PATH, &attr, sizeof attr) != 0)
        bad("mount_setattr(tree, noatime)", errno);
    expect("new-API remount,noatime", "rw,noatime", "rw");

    // `ro` is a SUPERBLOCK flag: super column ro, attachment still rw.
    if (xfsconfig(fs, X_FSCONFIG_SET_FLAG, "ro", NULL) != 0 ||
        xfsconfig(fs, X_FSCONFIG_CMD_RECONFIGURE, NULL, NULL) != 0)
        bad("fsconfig ro + CMD_RECONFIGURE", errno);
    expect("new-API remount,ro", "rw,noatime", "ro");
    int w = writable();
    if (w != -EROFS)
        bad("write to a read-only superblock must be EROFS", -w);
    if (xfsconfig(fs, X_FSCONFIG_SET_FLAG, "rw", NULL) != 0 ||
        xfsconfig(fs, X_FSCONFIG_CMD_RECONFIGURE, NULL, NULL) != 0)
        bad("fsconfig rw + CMD_RECONFIGURE", errno);
    if ((w = writable()) != 0)
        bad("reconfigure back to rw must be writable", -w);

    // Negative: an unknown filesystem parameter fails the reconfigure
    // (-EINVAL either at SET time, where Linux parses, or at RECONFIGURE).
    long set = xfsconfig(fs, X_FSCONFIG_SET_STRING, "not_a_tmpfs_option", "1");
    int set_errno = errno;
    long rec = set == 0 ? xfsconfig(fs, X_FSCONFIG_CMD_RECONFIGURE, NULL, NULL) : -1;
    int rec_errno = errno;
    if (!((set != 0 && set_errno == EINVAL) || (rec != 0 && rec_errno == EINVAL)))
        bad("an unknown tmpfs parameter must be EINVAL", set != 0 ? set_errno : rec_errno);
    close(fs);
    close(tree);

    // ── mount(2) MS_REMOUNT ─────────────────────────────────────────
    if (mount(NULL, mnt, NULL, MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, NULL) != 0)
        bad("mount(MS_REMOUNT|nosuid|nodev|noexec|noatime)", errno);
    expect("MS_REMOUNT flags", "rw,nosuid,nodev,noexec,noatime", "rw");
    // No atime flag: the atime policy is preserved.
    if (mount(NULL, mnt, NULL, MS_REMOUNT | MS_RDONLY, NULL) != 0)
        bad("mount(MS_REMOUNT|MS_RDONLY)", errno);
    expect("MS_REMOUNT ro", "ro,noatime", "ro");
    if ((w = writable()) != -EROFS)
        bad("write after MS_REMOUNT|MS_RDONLY must be EROFS", -w);
    if (mount(NULL, mnt, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID, NULL) != 0)
        bad("mount(MS_BIND|MS_REMOUNT|ro|nosuid)", errno);
    expect("MS_BIND|MS_REMOUNT", "ro,nosuid,noatime", "ro");
    if (mount(NULL, mnt, NULL, MS_REMOUNT | X_MS_STRICTATIME, NULL) != 0)
        bad("mount(MS_REMOUNT|MS_STRICTATIME)", errno);
    expect("MS_REMOUNT rw,strictatime", "rw", "rw");
    if ((w = writable()) != 0)
        bad("MS_REMOUNT rw must be writable", -w);

    // Negative: a remount of something that is not a mount point.
    char sub[256];
    snprintf(sub, sizeof sub, "%s/sub", mnt);
    mkdir(sub, 0755);
    if (mount(NULL, sub, NULL, MS_REMOUNT, NULL) == 0 || errno != EINVAL)
        bad("MS_REMOUNT of a non-mountpoint must be EINVAL", errno);
    // Negative: dirsync may not change on a remount (MS_RMT_MASK).
    if (mount(NULL, mnt, NULL, MS_REMOUNT | MS_RDONLY, "dirsync") == 0 || errno != EINVAL)
        bad("remount with dirsync must be EINVAL", errno);
    expect("refused remount leaves the mount alone", "rw", "rw");
    rmdir(sub);

    umount(mnt);
    rmdir(mnt);
    if (failures)
        return 1;
    printf("remount-ok\n");
    return 0;
}
