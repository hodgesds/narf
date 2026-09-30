// devpts mounts are independent instances with their own options (Linux 4.7+).
//
// fs/devpts/inode.c: every devpts mount is a new pts_fs_info with its own
// index allocator and mount options — uid=, gid=, mode= (default 0600),
// ptmxmode= (default 0000), max=, newinstance — applied when a pty is created
// (devpts_pty_new) and to the instance's own ptmx node (mknod_ptmx,
// update_ptmx_mode), shown in /proc/mounts (devpts_show_options), and reset
// to defaults then re-parsed on remount (devpts_reconfigure). A pty takes the
// lowest free index below max (devpts_new_index: ida_alloc_max), ENOSPC past
// it or past kernel.pty.max. drivers/tty/pty.c ptmx_open finds its instance
// through devpts_acquire: the devpts the ptmx node lives on, else a devpts
// mounted at "pts" beside it, else ENODEV.
//
// Runs as root (the NARF harness) or as root of a user+mount namespace
// (`unshare -rm`, how it is validated on a Linux host). Parts that need init
// namespace privileges (mknod of a ptmx node) are skipped when EPERM.
//
// Success token "devpts-instances-ok".
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int failed;

static void fail(const char *what, long v) {
    printf("devpts-instances-fail: %s (%ld)\n", what, v);
    failed = 1;
}

// The comma-separated option list of the mount at `dir` in /proc/self/mounts.
static int mount_opts(const char *dir, char *out, size_t n) {
    FILE *f = fopen("/proc/self/mounts", "r");
    if (!f)
        return -1;
    char line[1024];
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        char src[256], mnt[512], type[64], opts[512];
        if (sscanf(line, "%255s %511s %63s %511s", src, mnt, type, opts) == 4 &&
            strcmp(mnt, dir) == 0 && strcmp(type, "devpts") == 0) {
            snprintf(out, n, "%s", opts);
            found = 0;
        }
    }
    fclose(f);
    return found;
}

static int has_opt(const char *opts, const char *want) {
    size_t w = strlen(want);
    for (const char *p = opts; *p;) {
        const char *e = strchr(p, ',');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len == w && memcmp(p, want, w) == 0)
            return 1;
        if (!e)
            break;
        p = e + 1;
    }
    return 0;
}

static int ptn_of(int m) {
    unsigned n = 0;
    return ioctl(m, TIOCGPTN, &n) == 0 ? (int)n : -1;
}

static int unlock(int m) {
    int zero = 0;
    return ioctl(m, TIOCSPTLCK, &zero);
}

// Entries of `dir` other than "." and "..", as a count; `names` gets them.
static int list_dir(const char *dir, char *names, size_t n) {
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int count = 0;
    names[0] = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        count++;
        strncat(names, e->d_name, n - strlen(names) - 2);
        strncat(names, " ", n - strlen(names) - 1);
    }
    closedir(d);
    return count;
}

// The initial-namespace value of in-namespace id 0 (devpts_show_options prints
// uid=/gid= through from_k[ug]id_munged(&init_user_ns, ...)).
static long host_id0(const char *map) {
    FILE *f = fopen(map, "r");
    long inner, outer, count;
    long v = 0;
    if (f) {
        while (fscanf(f, "%ld %ld %ld", &inner, &outer, &count) == 3)
            if (inner == 0)
                v = outer;
        fclose(f);
    }
    return v;
}

static long read_long(const char *path) {
    FILE *f = fopen(path, "r");
    long v = -1;
    if (f) {
        if (fscanf(f, "%ld", &v) != 1)
            v = -1;
        fclose(f);
    }
    return v;
}

int main(void) {
    char base[] = "/tmp/devpts-inst-XXXXXX";
    if (!mkdtemp(base)) {
        printf("devpts-instances-fail: mkdtemp errno=%d\n", errno);
        return 1;
    }
    char a[256], b[256], path[512], opts[512], want_gid[32], want_uid[32];
    snprintf(want_gid, sizeof want_gid, "gid=%ld", host_id0("/proc/self/gid_map"));
    snprintf(want_uid, sizeof want_uid, "uid=%ld", host_id0("/proc/self/uid_map"));
    snprintf(a, sizeof a, "%s/a", base);
    snprintf(b, sizeof b, "%s/b", base);
    mkdir(a, 0755);
    mkdir(b, 0755);

    // ── kernel.pty sysctls ──
    if (read_long("/proc/sys/kernel/pty/max") != 4096)
        fail("kernel.pty.max is not 4096", read_long("/proc/sys/kernel/pty/max"));
    if (read_long("/proc/sys/kernel/pty/reserve") != 1024)
        fail("kernel.pty.reserve is not 1024", read_long("/proc/sys/kernel/pty/reserve"));
    long nr0 = read_long("/proc/sys/kernel/pty/nr");
    if (nr0 < 0)
        fail("kernel.pty.nr unreadable", nr0);

    // ── bad options are EINVAL ──
    if (mount("none", a, "devpts", 0, "bogus=1") != -1 || errno != EINVAL)
        fail("unknown option was not EINVAL, errno", errno);
    if (mount("none", a, "devpts", 0, "max=2000000") != -1 || errno != EINVAL)
        fail("max above NR_UNIX98_PTY_MAX was not EINVAL, errno", errno);

    // ── an instance with explicit options ──
    if (mount("none", a, "devpts", 0, "newinstance,mode=0620,gid=0,ptmxmode=0666,max=2") != 0) {
        printf("devpts-instances-fail: mount devpts errno=%d\n", errno);
        return 1;
    }
    if (mount_opts(a, opts, sizeof opts) != 0)
        fail("the mount is missing from /proc/self/mounts", 0);
    else if (!has_opt(opts, want_gid) || !has_opt(opts, "mode=620") ||
             !has_opt(opts, "ptmxmode=666") || !has_opt(opts, "max=2") || strstr(opts, "uid="))
        printf("devpts-instances-fail: shown options were \"%s\"\n", opts), failed = 1;

    // Its ptmx node: c 5:2, ptmxmode, the mounter's ids, inode 2.
    struct stat st, ms;
    snprintf(path, sizeof path, "%s/ptmx", a);
    if (stat(path, &st) != 0 || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(5, 2) ||
        (st.st_mode & 07777) != 0666 || st.st_uid != geteuid() || st.st_gid != getegid() ||
        st.st_ino != 2)
        fail("instance ptmx node identity (mode)", (long)st.st_mode);
    dev_t inst_dev = st.st_dev;

    // Its own index space, from 0, lowest-free, bounded by max.
    int m0 = open(path, O_RDWR | O_NOCTTY);
    int m1 = open(path, O_RDWR | O_NOCTTY);
    if (m0 < 0 || m1 < 0) {
        fail("open(instance ptmx) errno", errno);
    } else {
        if (ptn_of(m0) != 0 || ptn_of(m1) != 1)
            fail("instance indices do not start at 0 (second index)", ptn_of(m1));
        if (fstat(m0, &ms) != 0 || ms.st_ino != st.st_ino || ms.st_dev != st.st_dev ||
            ms.st_mode != st.st_mode)
            fail("fstat(master) is not its ptmx node's identity", (long)ms.st_ino);
        long nr = read_long("/proc/sys/kernel/pty/nr");
        if (nr != nr0 + 2)
            fail("kernel.pty.nr did not count two new ptys", nr - nr0);
        if (open(path, O_RDWR | O_NOCTTY) != -1 || errno != ENOSPC)
            fail("a third pty past max=2 was not ENOSPC, errno", errno);
        unlock(m0);
        unlock(m1);
        // The slave takes mode= and gid=, and lives on the instance's device.
        snprintf(path, sizeof path, "%s/0", a);
        if (stat(path, &st) != 0 || (st.st_mode & 07777) != 0620 || st.st_gid != 0 ||
            st.st_uid != geteuid() || st.st_rdev != makedev(136, 0) || st.st_dev != inst_dev ||
            st.st_ino != 3)
            fail("instance slave identity (mode)", (long)st.st_mode);
        char names[256];
        int n = list_dir(a, names, sizeof names);
        if (n != 3)
            printf("devpts-instances-fail: instance lists \"%s\"\n", names), failed = 1;
        // Lowest free index is reused.
        close(m0);
        snprintf(path, sizeof path, "%s/ptmx", a);
        int m2 = open(path, O_RDWR | O_NOCTTY);
        if (m2 < 0 || ptn_of(m2) != 0)
            fail("the freed index 0 was not reused (got)", m2 < 0 ? -errno : ptn_of(m2));
        if (m2 >= 0)
            close(m2);
        close(m1);
    }

    // ── remount resets to defaults, then applies the new options ──
    if (mount("none", a, "devpts", MS_REMOUNT, "mode=0600,ptmxmode=0600,uid=0") != 0)
        fail("remount errno", errno);
    if (mount_opts(a, opts, sizeof opts) != 0 || strstr(opts, "gid=") ||
        !has_opt(opts, want_uid) || !has_opt(opts, "mode=600") || !has_opt(opts, "ptmxmode=600") ||
        strstr(opts, "max="))
        printf("devpts-instances-fail: remounted options were \"%s\"\n", opts), failed = 1;
    snprintf(path, sizeof path, "%s/ptmx", a);
    if (stat(path, &st) != 0 || (st.st_mode & 07777) != 0600)
        fail("remount did not update the ptmx node mode", (long)(st.st_mode & 07777));
    int m3 = open(path, O_RDWR | O_NOCTTY);
    if (m3 < 0) {
        fail("open after remount errno", errno);
    } else {
        unlock(m3);
        snprintf(path, sizeof path, "%s/%d", a, ptn_of(m3));
        if (stat(path, &st) != 0 || (st.st_mode & 07777) != 0600 || st.st_uid != 0)
            fail("remount options not applied to a new pty (mode)", (long)(st.st_mode & 07777));
        close(m3);
    }

    // ── a second instance is independent ──
    if (mount("none", b, "devpts", 0, "") != 0) {
        fail("second mount errno", errno);
    } else {
        if (mount_opts(b, opts, sizeof opts) != 0 || !has_opt(opts, "mode=600") ||
            !has_opt(opts, "ptmxmode=000") || strstr(opts, "gid=") || strstr(opts, "uid=") ||
            strstr(opts, "max="))
            printf("devpts-instances-fail: default options were \"%s\"\n", opts), failed = 1;
        snprintf(path, sizeof path, "%s/ptmx", b);
        if (stat(path, &st) != 0 || (st.st_mode & 07777) != 0 || st.st_dev == inst_dev)
            fail("second instance ptmx identity (mode)", (long)(st.st_mode & 07777));
        int mb = open(path, O_RDWR | O_NOCTTY); // root bypasses the 0000 mode
        if (mb < 0 || ptn_of(mb) != 0)
            fail("second instance does not start at index 0 (got)", mb < 0 ? -errno : ptn_of(mb));
        char names[256];
        if (list_dir(a, names, sizeof names) != 1)
            printf("devpts-instances-fail: first instance lists \"%s\"\n", names), failed = 1;
        if (mb >= 0)
            close(mb);
        umount(b);
    }

    // ── a ptmx node outside devpts finds "pts" beside it, else ENODEV ──
    char d[256], dp[300], dptmx[300];
    snprintf(d, sizeof d, "%s/b", base);
    snprintf(dptmx, sizeof dptmx, "%s/ptmx", d);
    snprintf(dp, sizeof dp, "%s/pts", d);
    if (mknod(dptmx, S_IFCHR | 0666, makedev(5, 2)) == 0) {
        if (open(dptmx, O_RDWR | O_NOCTTY) != -1 || errno != ENODEV)
            fail("ptmx with no devpts beside it was not ENODEV, errno", errno);
        mkdir(dp, 0755);
        if (mount("none", dp, "devpts", 0, "ptmxmode=0666") == 0) {
            int mx = open(dptmx, O_RDWR | O_NOCTTY);
            if (mx < 0 || ptn_of(mx) != 0)
                fail("ptmx did not allocate in the devpts beside it (got)",
                     mx < 0 ? -errno : ptn_of(mx));
            struct stat node;
            if (mx >= 0 && (fstat(mx, &ms) != 0 || stat(dptmx, &node) != 0 ||
                            ms.st_ino != node.st_ino || ms.st_dev != node.st_dev))
                fail("fstat(master) is not the node it was opened through", (long)ms.st_ino);
            if (mx >= 0)
                close(mx);
            umount(dp);
        } else {
            fail("mount devpts at pts errno", errno);
        }
        unlink(dptmx);
        rmdir(dp);
    } else if (errno != EPERM) {
        fail("mknod ptmx errno", errno);
    }

    umount(a);
    rmdir(a);
    rmdir(b);
    rmdir(base);
    if (failed)
        return 1;
    printf("devpts-instances-ok\n");
    return 0;
}
