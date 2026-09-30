// /proc/self/fd/N is a magic link: following it jumps to the fd's own file,
// even when that file is a symlink opened with O_PATH|O_NOFOLLOW.
//
// systemd PID 1 watches /etc/localtime (a symlink) for timezone changes:
// sd-event opens it with O_PATH|O_CLOEXEC|O_NOFOLLOW and then calls
// inotify_add_watch(ifd, "/proc/self/fd/N", mask) (sd-event.c,
// inotify-util.c:inotify_add_watch_fd). On Linux the lookup follows the magic
// link to the symlink inode itself (proc_fd_link -> nd_jump_link); NARF
// returned ENOENT, which systemd reports as "Failed to create timezone change
// event source: Bad file descriptor" (proc_fd_enoent_errno maps ENOENT to
// EBADF when /proc is mounted).
//
// For a symlink, a regular file and a directory opened with O_PATH:
//   - stat("/proc/self/fd/N") reports the fd's own inode (the symlink, not
//     its target), as fstat(N) does;
//   - inotify_add_watch(ifd, "/proc/self/fd/N", ...) succeeds;
//   - the watch is on that inode: changing its attributes delivers IN_ATTRIB.
//
// Success token "proc-fd-magiclink-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int failed;

static void fail(const char *kind, const char *what, int err) {
    printf("proc-fd-magiclink-fail: %s: %s (errno %d)\n", kind, what, err);
    fflush(stdout);
    failed = 1;
}

// Wait up to 1 s for an event on `ifd` whose mask includes `want`.
static int got_event(int ifd, int wd, unsigned want) {
    struct pollfd p = {ifd, POLLIN, 0};
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (int tries = 0; tries < 10; tries++) {
        if (poll(&p, 1, 100) != 1)
            continue;
        ssize_t n = read(ifd, buf, sizeof buf);
        for (char *q = buf; n > 0 && q < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)q;
            if (ev->wd == wd && (ev->mask & want))
                return 1;
            q += sizeof *ev + ev->len;
        }
    }
    return 0;
}

// `touch` the inode behind `path` without following a final symlink.
static int touch_nofollow(const char *path) {
    struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    return utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
}

static void check(const char *kind, const char *path, int open_flags, mode_t want_type) {
    int fd = open(path, open_flags);
    if (fd < 0) {
        fail(kind, "open O_PATH", errno);
        return;
    }
    char magic[64];
    snprintf(magic, sizeof magic, "/proc/self/fd/%d", fd);

    struct stat by_fd, by_magic, by_lstat;
    if (fstat(fd, &by_fd) != 0 || lstat(path, &by_lstat) != 0) {
        fail(kind, "fstat/lstat", errno);
        close(fd);
        return;
    }
    if (stat(magic, &by_magic) != 0) {
        fail(kind, "stat(/proc/self/fd/N) failed", errno);
    } else {
        if ((by_magic.st_mode & S_IFMT) != want_type)
            fail(kind, "stat(/proc/self/fd/N) did not land on the fd's own file type", 0);
        if (by_magic.st_ino != by_fd.st_ino || by_magic.st_dev != by_fd.st_dev)
            fail(kind, "stat(/proc/self/fd/N) is not the inode fstat(N) reports", 0);
        if (by_magic.st_ino != by_lstat.st_ino)
            fail(kind, "stat(/proc/self/fd/N) is not the path's own (lstat) inode", 0);
    }

#ifdef STATX_INO
    struct statx sx;
    if (statx(AT_FDCWD, magic, 0, STATX_TYPE | STATX_INO, &sx) != 0) {
        fail(kind, "statx(/proc/self/fd/N) failed", errno);
    } else if (sx.stx_ino != by_fd.st_ino || (sx.stx_mode & S_IFMT) != want_type) {
        fail(kind, "statx(/proc/self/fd/N) is not the fd's own inode", 0);
    }
#endif

    // systemd's exact call: IN_DONT_FOLLOW stripped, the magic link followed.
    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    int wd = inotify_add_watch(ifd, magic, IN_ATTRIB | IN_MOVE_SELF | IN_CLOSE_WRITE);
    if (wd < 0) {
        fail(kind, "inotify_add_watch(/proc/self/fd/N) failed", errno);
    } else {
        if (touch_nofollow(path) != 0)
            fail(kind, "utimensat(AT_SYMLINK_NOFOLLOW)", errno);
        else if (!got_event(ifd, wd, IN_ATTRIB))
            fail(kind, "no IN_ATTRIB: the watch is not on the fd's own inode", 0);
    }
    close(ifd);
    close(fd);
}

int main(void) {
    char dir[] = "/tmp/magiclink.XXXXXX";
    if (!mkdtemp(dir)) {
        fail("setup", "mkdtemp", errno);
        return 1;
    }
    char file[64], link[64], sub[64];
    snprintf(file, sizeof file, "%s/target", dir);
    snprintf(link, sizeof link, "%s/localtime", dir);
    snprintf(sub, sizeof sub, "%s/sub", dir);
    int t = open(file, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (t < 0 || symlink(file, link) != 0 || mkdir(sub, 0755) != 0) {
        fail("setup", "create files", errno);
        return 1;
    }
    close(t);

    // /etc/localtime shape: the symlink itself, via O_PATH|O_NOFOLLOW.
    check("symlink", link, O_PATH | O_CLOEXEC | O_NOFOLLOW, S_IFLNK);
    check("file", file, O_PATH | O_CLOEXEC, S_IFREG);
    check("directory", sub, O_PATH | O_CLOEXEC, S_IFDIR);

    unlink(link);
    unlink(file);
    rmdir(sub);
    rmdir(dir);
    if (failed)
        return 1;
    printf("proc-fd-magiclink-ok\n");
    return 0;
}
