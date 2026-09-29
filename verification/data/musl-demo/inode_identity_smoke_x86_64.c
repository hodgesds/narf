// Every open file has an inode: (st_dev, st_ino) is nonzero, stable, and
// Linux-shaped for each kind of file.
//
// userspace relies on the pair: flock(2) conflicts per inode, systemd matches
// a stream fd against $JOURNAL_STREAM, find/du/tar/rsync detect hardlinks,
// musl dedups shared objects, fish notices fish_variables changing.
//
// Linux model checked here:
//   pipe(2)       one pipefs inode per pipe, shared by both ends
//   socket(2)     one sockfs inode per socket (socketpair: two)
//   eventfd, epoll, signalfd, timerfd, inotify
//                 all share the single anon_inodefs inode
//   memfd_create  one shmem inode per memfd
//   pidfd_open    pidfs (6.9+): one inode per process, the same for two
//                 pidfds of one process
//   /proc, /sys, /dev, /tmp files
//                 nonzero and stable across repeated stat()
//   dup, fork     the same inode
//
// Success token "inode-identity-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

static int failed;

static void fail(const char *what) {
    char buf[160];
    int n = snprintf(buf, sizeof buf, "inode-identity-fail: %s\n", what);
    write(1, buf, n);
    failed = 1;
}

static int id_of(int fd, struct stat *st) {
    if (fstat(fd, st) != 0)
        return -1;
    return 0;
}

static int same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static void need_nonzero(const char *what, int fd) {
    struct stat st;
    if (fd < 0 || id_of(fd, &st) != 0) {
        char m[96];
        snprintf(m, sizeof m, "%s: open/fstat failed (errno %d)", what, errno);
        fail(m);
        return;
    }
    if (st.st_ino == 0) {
        char m[96];
        snprintf(m, sizeof m, "%s: st_ino is 0", what);
        fail(m);
    }
}

static void check_path_stable(const char *path) {
    struct stat a, b;
    if (stat(path, &a) != 0)
        return; // not present in this environment
    if (a.st_ino == 0) {
        char m[128];
        snprintf(m, sizeof m, "%s: st_ino is 0", path);
        fail(m);
    }
    if (stat(path, &b) != 0 || !same(&a, &b)) {
        char m[128];
        snprintf(m, sizeof m, "%s: (st_dev, st_ino) changed between two stat()s", path);
        fail(m);
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        struct stat c;
        if (fstat(fd, &c) != 0 || !same(&a, &c)) {
            char m[128];
            snprintf(m, sizeof m, "%s: fstat of an open fd differs from stat()", path);
            fail(m);
        }
        close(fd);
    }
}

int main(void) {
    struct stat a, b, c;

    // pipes: both ends share one inode; two pipes differ.
    int p1[2], p2[2];
    if (pipe(p1) != 0 || pipe(p2) != 0) {
        fail("pipe");
    } else {
        need_nonzero("pipe read end", p1[0]);
        id_of(p1[0], &a);
        id_of(p1[1], &b);
        id_of(p2[0], &c);
        if (!same(&a, &b))
            fail("pipe: the two ends of one pipe report different inodes");
        if (same(&a, &c))
            fail("pipe: two pipes share an inode");
    }

    // sockets: one inode per socket.
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        fail("socketpair");
    } else {
        need_nonzero("socket", sp[0]);
        id_of(sp[0], &a);
        id_of(sp[1], &b);
        if (same(&a, &b))
            fail("socketpair: both sockets share an inode");
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            id_of(s, &c);
            if (same(&a, &c))
                fail("socket: two sockets share an inode");
        }
    }

    // anon-inode files: all share the one anon_inodefs inode.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    int anon[5] = {
        eventfd(0, EFD_CLOEXEC),
        epoll_create1(EPOLL_CLOEXEC),
        signalfd(-1, &mask, SFD_CLOEXEC),
        timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC),
        inotify_init1(IN_CLOEXEC),
    };
    static const char *anon_name[5] = {"eventfd", "epoll", "signalfd", "timerfd", "inotify"};
    struct stat anon_st[5];
    for (int i = 0; i < 5; i++) {
        need_nonzero(anon_name[i], anon[i]);
        id_of(anon[i], &anon_st[i]);
    }
    for (int i = 1; i < 5; i++)
        if (!same(&anon_st[0], &anon_st[i])) {
            char m[96];
            snprintf(m, sizeof m, "%s does not share eventfd's anon inode", anon_name[i]);
            fail(m);
        }
    int ev2 = eventfd(0, EFD_CLOEXEC);
    id_of(ev2, &b);
    if (!same(&anon_st[0], &b))
        fail("two eventfds report different inodes (Linux: one anon inode)");

    // memfd: one inode per memfd.
    int m1 = memfd_create("a", MFD_CLOEXEC), m2 = memfd_create("b", MFD_CLOEXEC);
    need_nonzero("memfd", m1);
    id_of(m1, &a);
    id_of(m2, &b);
    if (same(&a, &b))
        fail("memfd: two memfds share an inode");

    // pidfd (pidfs, Linux 6.9+): per process, same for two pidfds of one pid.
    pid_t child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    int pf1 = (int)syscall(SYS_pidfd_open, child, 0);
    int pf2 = (int)syscall(SYS_pidfd_open, child, 0);
    int pfself = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pf1 >= 0 && pf2 >= 0 && pfself >= 0) {
        need_nonzero("pidfd", pf1);
        id_of(pf1, &a);
        id_of(pf2, &b);
        id_of(pfself, &c);
        if (!same(&a, &b))
            fail("pidfd: two pidfds of one process report different inodes");
        if (same(&a, &c))
            fail("pidfd: two processes' pidfds share an inode");
    } else {
        fail("pidfd_open");
    }

    // dup and fork keep the identity.
    int d = dup(p1[0]);
    id_of(p1[0], &a);
    id_of(d, &b);
    if (!same(&a, &b))
        fail("dup changed the inode");
    int chk[2];
    pipe(chk);
    pid_t f = fork();
    if (f == 0) {
        struct stat s2;
        fstat(p1[0], &s2);
        char ok = same(&a, &s2) ? 'y' : 'n';
        write(chk[1], &ok, 1);
        _exit(0);
    }
    char ok = 'n';
    read(chk[0], &ok, 1);
    waitpid(f, NULL, 0);
    if (ok != 'y')
        fail("fork changed the inode of an inherited fd");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // Filesystem-backed files: nonzero and stable.
    static const char *paths[] = {
        "/proc/self/status", "/proc/self/stat",  "/proc/meminfo",  "/proc/self",
        "/proc/self/fd",     "/proc/self/ns/pid", "/sys/kernel",   "/sys/class",
        "/dev/null",         "/dev/zero",        "/dev/urandom",   "/dev/tty",
        "/tmp",              "/",
    };
    for (unsigned i = 0; i < sizeof paths / sizeof paths[0]; i++)
        check_path_stable(paths[i]);

    if (failed)
        return 1;
    write(1, "inode-identity-ok\n", 18);
    return 0;
}
