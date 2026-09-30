// Mounting a pseudo filesystem onto an occupied mountpoint stacks a new mount.
//
// Linux attaches every mount(2) of a new filesystem on top of whatever is
// mounted at the target (do_new_mount → do_add_mount; an overmount hides the
// mount below until it is unmounted). NARF answered a second mount of a
// "pseudo" filesystem (tmpfs, proc, devpts, ...) onto an already-mounted path
// with success but mounted nothing — a workaround from before NARF had mount
// stacking — so systemd's devpts mount over the boot /dev/pts never created
// its own instance and a second tmpfs left the first one's files visible.
//
//   - tmpfs over tmpfs: the lower mount's file is hidden while the upper one
//     is mounted, both appear in /proc/self/mounts, umount reveals it again;
//   - devpts over devpts: the upper mount is a new instance — its own index
//     space (index 0 again) and its own options — and umount returns to the
//     lower instance.
//
// Runs as root (the NARF harness) or as root of a user+mount namespace
// (`unshare -rm`, how it is validated on a Linux host).
//
// Success token "overmount-pseudo-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int failed;

static void fail(const char *what, long v) {
    printf("overmount-pseudo-fail: %s (%ld)\n", what, v);
    failed = 1;
}

// Mounts of `type` at `dir` in /proc/self/mounts; `last_opts` gets the last.
static int count_mounts(const char *dir, const char *type, char *last_opts, size_t n) {
    FILE *f = fopen("/proc/self/mounts", "r");
    if (!f)
        return -1;
    char line[1024];
    int count = 0;
    while (fgets(line, sizeof line, f)) {
        char src[256], mnt[512], t[64], opts[512];
        if (sscanf(line, "%255s %511s %63s %511s", src, mnt, t, opts) == 4 &&
            strcmp(mnt, dir) == 0 && strcmp(t, type) == 0) {
            count++;
            if (last_opts)
                snprintf(last_opts, n, "%s", opts);
        }
    }
    fclose(f);
    return count;
}

static int ptn_of(int m) {
    unsigned n = 0;
    return ioctl(m, TIOCGPTN, &n) == 0 ? (int)n : -1;
}

int main(void) {
    char base[] = "/tmp/overmount-XXXXXX";
    if (!mkdtemp(base)) {
        printf("overmount-pseudo-fail: mkdtemp errno=%d\n", errno);
        return 1;
    }
    char path[512], opts[512];

    // ── tmpfs over tmpfs ──
    if (mount("lower", base, "tmpfs", 0, "mode=0755") != 0) {
        printf("overmount-pseudo-fail: mount tmpfs errno=%d\n", errno);
        return 1;
    }
    snprintf(path, sizeof path, "%s/lower-file", base);
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0)
        fail("create in lower tmpfs errno", errno);
    else
        close(fd);
    if (mount("upper", base, "tmpfs", 0, "mode=0700") != 0)
        fail("second tmpfs mount errno", errno);
    else {
        if (access(path, F_OK) == 0)
            fail("the lower tmpfs's file is still visible under the overmount", 0);
        if (count_mounts(base, "tmpfs", NULL, 0) != 2)
            fail("tmpfs mounts at the path", count_mounts(base, "tmpfs", NULL, 0));
        struct stat st;
        if (stat(base, &st) != 0 || (st.st_mode & 07777) != 0700)
            fail("the path does not show the upper tmpfs root (mode)", (long)(st.st_mode & 07777));
        if (umount(base) != 0)
            fail("umount upper tmpfs errno", errno);
        if (access(path, F_OK) != 0)
            fail("umount did not reveal the lower tmpfs's file", errno);
    }
    unlink(path);
    umount(base);

    // ── devpts over devpts ──
    if (mount("none", base, "devpts", 0, "ptmxmode=0666,max=5") != 0) {
        printf("overmount-pseudo-fail: mount devpts errno=%d\n", errno);
        return 1;
    }
    snprintf(path, sizeof path, "%s/ptmx", base);
    int lower = open(path, O_RDWR | O_NOCTTY);
    if (lower < 0 || ptn_of(lower) != 0)
        fail("lower devpts first index (got)", lower < 0 ? -errno : ptn_of(lower));
    if (mount("none", base, "devpts", 0, "ptmxmode=0600,mode=0620") != 0) {
        fail("second devpts mount errno", errno);
    } else {
        if (count_mounts(base, "devpts", opts, sizeof opts) != 2)
            fail("devpts mounts at the path", count_mounts(base, "devpts", NULL, 0));
        else if (!strstr(opts, "ptmxmode=600") || strstr(opts, "max=5"))
            printf("overmount-pseudo-fail: upper devpts options were \"%s\"\n", opts), failed = 1;
        int upper = open(path, O_RDWR | O_NOCTTY);
        if (upper < 0 || ptn_of(upper) != 0)
            fail("upper devpts is not a new instance (first index)", upper < 0 ? -errno : ptn_of(upper));
        if (upper >= 0)
            close(upper);
        if (umount(base) != 0)
            fail("umount upper devpts errno", errno);
        // The lower instance again: its ptmx mode and its live pty 0.
        struct stat st;
        snprintf(path, sizeof path, "%s/ptmx", base);
        if (stat(path, &st) != 0 || (st.st_mode & 07777) != 0666)
            fail("umount did not return to the lower devpts (ptmx mode)", (long)(st.st_mode & 07777));
    }
    if (lower >= 0)
        close(lower);
    umount(base);
    rmdir(base);
    if (failed)
        return 1;
    printf("overmount-pseudo-ok\n");
    return 0;
}
