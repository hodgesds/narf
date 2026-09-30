// A dup()'d descriptor survives execve; FD_CLOEXEC ones do not.
//
// kwin launches Xwayland with a pre-connected Wayland socket: it creates a
// socketpair with SOCK_CLOEXEC, dup()s one end (dup clears FD_CLOEXEC),
// exports the number as WAYLAND_SOCKET=<n>, and passes the X listening
// sockets as "-listenfd <n>". In the exec'd Xwayland, libwayland's
// wl_display_connect() does fcntl(n, F_GETFD) (EBADF -> fail), sets
// FD_CLOEXEC on it, and talks Wayland over it. On NARF Xwayland printed
// "could not connect to wayland server" and exited 1, in a restart loop,
// so every X client (xrdb, xprop) hung and the Plasma session never started.
//
// kwin actually does it Qt's QProcess::UnixProcessFlag::UseVFork way: Qt's
// forkfd calls glibc clone(fn, stack, CLONE_PIDFD|CLONE_VFORK|CLONE_VM|SIGCHLD)
// and kwin's child-process modifier clears FD_CLOEXEC with fcntl(F_SETFD) on
// the original SOCK_CLOEXEC sockets inside the child, right before execve.
//
// Launch paths: fork+execve, vfork+execve, posix_spawn, and that Qt vforkfd
// clone. The exec'd child must see:
//   - the dup()'d socketpair end (fork/vfork/spawn) or the SOCK_CLOEXEC end
//     whose flag the child cleared (Qt clone) open, without FD_CLOEXEC, and
//     connected (a round trip with the parent works);
//   - a dup2()'d and an F_DUPFD'd copy open without FD_CLOEXEC;
//   - an F_DUPFD_CLOEXEC copy closed, and the SOCK_CLOEXEC end closed unless
//     the child cleared its flag.
//
// A shared fd table (CLONE_FILES) is unshared by exec before the
// close-on-exec sweep (begin_new_exec: unshare_files, then
// do_close_on_exec), so a CLONE_VM|CLONE_FILES|CLONE_VFORK child's exec must
// not close the parent's FD_CLOEXEC descriptors. unshare(CLONE_FILES) likewise
// gives the caller a private copy: a later close() leaves the other sharer's
// fd open, while without it the close is visible to both.
//
// Success token "fd-inherit-exec-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

extern char **environ;

// Exec'd child: argv = self --child <keep|gone>:<fd>... ; the first keep fd
// is WAYLAND_SOCKET.
static int child_main(int argc, char **argv) {
    int bad = 0, wl = -1;
    const char *env = getenv("WAYLAND_SOCKET");
    for (int i = 2; i < argc; i++) {
        int keep = strncmp(argv[i], "keep:", 5) == 0;
        int fd = atoi(argv[i] + 5);
        int fl = fcntl(fd, F_GETFD);
        if (keep) {
            if (wl < 0)
                wl = fd;
            if (fl == -1) {
                printf("fd-inherit-exec-fail: fd %d not inherited across exec (errno %d)\n", fd,
                       errno);
                bad = 1;
            } else if (fl & FD_CLOEXEC) {
                printf("fd-inherit-exec-fail: inherited fd %d carries FD_CLOEXEC\n", fd);
                bad = 1;
            }
        } else if (fl != -1 || errno != EBADF) {
            printf("fd-inherit-exec-fail: FD_CLOEXEC fd %d survived exec\n", fd);
            bad = 1;
        }
    }
    if (!env || atoi(env) != wl) {
        printf("fd-inherit-exec-fail: WAYLAND_SOCKET not inherited\n");
        return 1;
    }
    // libwayland's wl_display_connect: F_GETFD (EBADF -> fail), set
    // FD_CLOEXEC, then use the socket.
    if (fcntl(wl, F_SETFD, FD_CLOEXEC) != 0) {
        printf("fd-inherit-exec-fail: F_SETFD on the inherited fd (errno %d)\n", errno);
        bad = 1;
    }
    char c = 0;
    if (write(wl, "p", 1) != 1 || read(wl, &c, 1) != 1 || c != 'q') {
        printf("fd-inherit-exec-fail: round trip over the inherited socket failed (errno %d)\n",
               errno);
        bad = 1;
    }
    return bad;
}

struct qt_child {
    const char *self;
    char **argv;
    int clear[2];
};

// kwin's child-process modifier followed by Qt's execve.
static int qt_child_fn(void *arg) {
    struct qt_child *q = arg;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(q->clear[i], F_GETFD);
        if (fl < 0 || fcntl(q->clear[i], F_SETFD, fl & ~FD_CLOEXEC) < 0)
            _exit(126);
    }
    execve(q->self, q->argv, environ);
    _exit(127);
}

static int launch(int how, const char *self) {
    int sv[2], wm[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return -1;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, wm) != 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    int dupfd = -1, dup2fd = -1, fdupfd = -1;
    int cloexecfd = fcntl(sv[1], F_DUPFD_CLOEXEC, 60);
    char a[6][24];
    int n = 0;
    if (how == 3) {
        // Qt: pass the SOCK_CLOEXEC ends; the child clears the flag.
        snprintf(a[n++], 24, "keep:%d", sv[1]);
        snprintf(a[n++], 24, "keep:%d", wm[1]);
    } else {
        dupfd = dup(sv[1]);
        dup2fd = dup2(sv[1], 40);
        fdupfd = fcntl(sv[1], F_DUPFD, 50);
        snprintf(a[n++], 24, "keep:%d", dupfd);
        snprintf(a[n++], 24, "keep:%d", dup2fd);
        snprintf(a[n++], 24, "keep:%d", fdupfd);
        snprintf(a[n++], 24, "gone:%d", sv[1]);
        snprintf(a[n++], 24, "gone:%d", wm[1]);
    }
    snprintf(a[n++], 24, "gone:%d", cloexecfd);
    char wlenv[16];
    snprintf(wlenv, sizeof wlenv, "%d", how == 3 ? sv[1] : dupfd);
    setenv("WAYLAND_SOCKET", wlenv, 1);
    char *argv[9] = {(char *)self, "--child"};
    for (int i = 0; i < n; i++)
        argv[2 + i] = a[i];
    argv[2 + n] = NULL;
    pid_t pid;
    if (how == 3) {
        static char stack[64 * 1024] __attribute__((aligned(64)));
        struct qt_child q = {self, argv, {sv[1], wm[1]}};
        int pidfd = -1;
        pid = clone(qt_child_fn, stack + sizeof stack,
                    CLONE_PIDFD | CLONE_VFORK | CLONE_VM | SIGCHLD, &q, &pidfd, NULL, NULL);
        if (pid < 0)
            printf("fd-inherit-exec-fail: vforkfd clone (errno %d)\n", errno);
        if (pidfd >= 0)
            close(pidfd);
    } else if (how == 2) {
        if (posix_spawn(&pid, self, NULL, NULL, argv, environ) != 0)
            pid = -1;
    } else {
        pid = how == 1 ? vfork() : fork();
        if (pid == 0) {
            execve(self, argv, environ);
            _exit(127);
        }
    }
    if (dupfd >= 0) {
        close(dupfd);
        close(dup2fd);
        close(fdupfd);
    }
    close(cloexecfd);
    close(sv[1]);
    close(wm[1]);
    char c = 0;
    // Serve the child's round trip.
    if (pid > 0 && read(sv[0], &c, 1) == 1 && c == 'p')
        (void)write(sv[0], "q", 1);
    int st = 0;
    if (pid > 0)
        waitpid(pid, &st, 0);
    close(sv[0]);
    close(wm[0]);
    unsetenv("WAYLAND_SOCKET");
    if (pid <= 0)
        return -1;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : 1;
}

struct files_child {
    const char *self;
    char **argv;
};

static int files_child_fn(void *arg) {
    struct files_child *f = arg;
    execve(f->self, f->argv, environ);
    _exit(127);
}

// A CLONE_VM|CLONE_FILES|CLONE_VFORK child execs: exec unshares the table
// before closing FD_CLOEXEC fds, so the parent keeps its own.
static int check_shared_table_exec(const char *self) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
        return 1;
    int keep = dup(sv[1]);
    int cloexecfd = fcntl(sv[1], F_DUPFD_CLOEXEC, 70);
    char a[3][24];
    snprintf(a[0], 24, "keep:%d", keep);
    snprintf(a[1], 24, "gone:%d", sv[1]);
    snprintf(a[2], 24, "gone:%d", cloexecfd);
    char wlenv[16];
    snprintf(wlenv, sizeof wlenv, "%d", keep);
    setenv("WAYLAND_SOCKET", wlenv, 1);
    char *argv[] = {(char *)self, "--child", a[0], a[1], a[2], NULL};
    static char stack[64 * 1024] __attribute__((aligned(64)));
    struct files_child f = {self, argv};
    int bad = 0;
    pid_t pid = clone(files_child_fn, stack + sizeof stack,
                      CLONE_VM | CLONE_FILES | CLONE_VFORK | SIGCHLD, &f);
    if (pid < 0) {
        printf("fd-inherit-exec-fail: CLONE_FILES clone (errno %d)\n", errno);
        bad = 1;
    } else {
        char c = 0;
        if (read(sv[0], &c, 1) == 1 && c == 'p')
            (void)write(sv[0], "q", 1);
        int st = 0;
        waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            printf("fd-inherit-exec-fail: CLONE_FILES exec'd child (status %#x)\n", st);
            bad = 1;
        }
        // The child is gone and its exec is long done: the parent's
        // close-on-exec fds must be untouched.
        if (fcntl(sv[1], F_GETFD) == -1 || fcntl(cloexecfd, F_GETFD) == -1) {
            printf("fd-inherit-exec-fail: a CLONE_FILES child's exec closed the parent's "
                   "FD_CLOEXEC fds\n");
            bad = 1;
        }
    }
    unsetenv("WAYLAND_SOCKET");
    close(sv[0]);
    close(sv[1]);
    close(keep);
    close(cloexecfd);
    return bad;
}

// A fork-shaped CLONE_FILES child closes an fd, with and without first
// calling unshare(CLONE_FILES). Returns whether the parent's fd survived.
static int shared_close_survives(int do_unshare, int *err) {
    int p[2];
    if (pipe(p) != 0) {
        *err = errno;
        return -1;
    }
    pid_t pid = (pid_t)syscall(SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if (pid == 0) {
        if (do_unshare && unshare(CLONE_FILES) != 0)
            _exit(2);
        close(p[0]);
        _exit(0);
    }
    if (pid < 0) {
        *err = errno;
        return -1;
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        *err = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        return -1;
    }
    int alive = fcntl(p[0], F_GETFD) != -1;
    if (alive)
        close(p[0]);
    close(p[1]);
    return alive;
}

static int check_unshare_files(void) {
    int bad = 0, err = 0;
    int r = shared_close_survives(0, &err);
    if (r != 0) {
        printf("fd-inherit-exec-fail: CLONE_FILES child's close() %s (err %d)\n",
               r < 0 ? "failed" : "did not reach the parent's shared table", err);
        bad = 1;
    }
    r = shared_close_survives(1, &err);
    if (r != 1) {
        printf("fd-inherit-exec-fail: after unshare(CLONE_FILES) a child's close() %s (err %d)\n",
               r < 0 ? "failed" : "still closed the parent's fd", err);
        bad = 1;
    }
    return bad;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--child") == 0)
        return child_main(argc, argv);
    char self[512];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0)
        return 1;
    self[n] = 0;
    static const char *how_name[] = {"fork+execve", "vfork+execve", "posix_spawn",
                                     "Qt vforkfd clone(CLONE_VM|CLONE_VFORK|CLONE_PIDFD)"};
    int failed = 0;
    for (int how = 0; how < 4; how++) {
        int r = launch(how, self);
        if (r != 0) {
            printf("fd-inherit-exec-fail: launch path %s\n", how_name[how]);
            failed = 1;
        }
    }
    failed |= check_shared_table_exec(self);
    failed |= check_unshare_files();
    if (failed)
        return 1;
    printf("fd-inherit-exec-ok\n");
    return 0;
}
