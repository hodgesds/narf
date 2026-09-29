// flock(2) locks belong to the open file description and conflict per inode.
//
// fish's history save: one thread opens ~/.local/share/fish (a directory),
// dups it (F_DUPFD_CLOEXEC), takes LOCK_SH, reads, closes; later the main
// thread opens the directory again and takes LOCK_EX. Meanwhile the main
// thread posix_spawn()s children, whose fd-table copies briefly reference the
// locked description until exec closes the O_CLOEXEC fds. If a description
// outlives its last close (a leaked reference), the lock is never released and
// the LOCK_EX blocks until a signal (Ctrl-C) interrupts it.
//
// Linux rules (fs/locks.c): a flock is released when the last descriptor of
// its open file description is closed (or on LOCK_UN); dup/fork aliases share
// the lock; two independent open()s of one inode conflict; exec closes
// O_CLOEXEC descriptors, dropping their references.
//
// Every lock uses LOCK_NB (setup locks never conflict on Linux) so a leak
// is a named failure, not a hang.
// Success token "flock-release-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static char self_path[PATH_MAX];
static const char *target;
static const char *kind;

static void w(const char *m) { write(1, m, strlen(m)); }

static int fail(const char *what, int err) {
    char buf[160];
    int n = snprintf(buf, sizeof buf, "flock-release-fail: %s: %s (errno %d)\n", kind, what, err);
    write(1, buf, n);
    return 1;
}

// open + F_DUPFD_CLOEXEC to a high fd + close the original, like fish.
static int open_dup(void) {
    int fd = open(target, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int dup = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    close(fd);
    return dup;
}

// Can a fresh description take LOCK_EX right now? 1 yes, 0 conflict, -1 error.
static int ex_available(void) {
    int fd = open_dup();
    if (fd < 0)
        return -1;
    int r = flock(fd, LOCK_EX | LOCK_NB);
    int err = errno;
    close(fd);
    if (r == 0)
        return 1;
    return err == EWOULDBLOCK ? 0 : -1;
}

static void *sh_then_close(void *arg) {
    (void)arg;
    int fd = open_dup();
    if (fd < 0 || flock(fd, LOCK_SH | LOCK_NB) != 0)
        return (void *)1;
    close(fd);
    return NULL;
}

// A: a sibling thread's LOCK_SH is released by its close().
static int case_thread_close(void) {
    pthread_t t;
    void *ret;
    pthread_create(&t, NULL, sh_then_close, NULL);
    pthread_join(t, &ret);
    if (ret)
        return fail("thread LOCK_SH (A) conflicted: a lock that should be free is held", errno);
    int r = ex_available();
    if (r != 1)
        return fail("LOCK_EX conflicts after the LOCK_SH holder closed its fd", errno);
    return 0;
}

// B: a spawned child's exec drops its O_CLOEXEC copy, so closing ours
// releases the lock while the child is still running.
static int case_spawn_exec(void) {
    int fd = open_dup();
    if (fd < 0 || flock(fd, LOCK_SH | LOCK_NB) != 0)
        return fail("LOCK_SH (B) conflicted: a lock that should be free is held", errno);
    pid_t child;
    char *argv[] = {self_path, "--sleep-ms", "300", NULL};
    if (posix_spawn(&child, self_path, NULL, NULL, argv, environ) != 0)
        return fail("posix_spawn", errno);
    usleep(100 * 1000); // the child has exec'd and is sleeping
    close(fd);
    int r = ex_available();
    waitpid(child, NULL, 0);
    if (r != 1)
        return fail("lock still held after close: the exec'd child kept an O_CLOEXEC reference", errno);
    return 0;
}

// C: a forked child that does NOT exec shares the description, so the lock
// stays until the child exits; then it is released.
static int case_fork_inherit(void) {
    int fd = open_dup();
    if (fd < 0 || flock(fd, LOCK_SH | LOCK_NB) != 0)
        return fail("LOCK_SH (C) conflicted: a lock that should be free is held", errno);
    int go[2];
    if (pipe(go) != 0)
        return fail("pipe", errno);
    pid_t child = fork();
    if (child == 0) {
        char c;
        close(go[1]);
        (void)read(go[0], &c, 1);
        _exit(0);
    }
    close(go[0]);
    close(fd);
    int held = ex_available();
    close(go[1]); // let the child exit
    waitpid(child, NULL, 0);
    int after = ex_available();
    if (held != 0)
        return fail("LOCK_EX succeeded while a forked child still shared the LOCK_SH description", 0);
    if (after != 1)
        return fail("lock not released after the forked child exited", errno);
    return 0;
}

// D: two independent open()s of one inode conflict (the lock is per inode).
static int case_independent_opens(void) {
    int a = open_dup();
    int b = open_dup();
    if (a < 0 || b < 0)
        return fail("open", errno);
    if (flock(a, LOCK_EX | LOCK_NB) != 0)
        return fail("first LOCK_EX", errno);
    int r = flock(b, LOCK_EX | LOCK_NB);
    int err = errno;
    close(a);
    int after = flock(b, LOCK_EX | LOCK_NB);
    close(b);
    if (r == 0)
        return fail("a second open() of the same inode took LOCK_EX without conflict", 0);
    if (err != EWOULDBLOCK)
        return fail("conflict errno is not EWOULDBLOCK", err);
    if (after != 0)
        return fail("LOCK_EX not available after the other description closed", errno);
    return 0;
}

static int run_all(void) {
    int failed = 0;
    failed |= case_thread_close();
    failed |= case_spawn_exec();
    failed |= case_fork_inherit();
    failed |= case_independent_opens();
    return failed;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--sleep-ms") == 0) {
        usleep(atoi(argv[2]) * 1000);
        return 0;
    }
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (n > 0)
        self_path[n] = 0;
    else
        snprintf(self_path, sizeof self_path, "%s", argv[0]);

    char dir[] = "/tmp/flock-release.XXXXXX";
    if (!mkdtemp(dir))
        return fail("mkdtemp", errno);
    char file[64];
    snprintf(file, sizeof file, "%s/file", dir);
    int fd = open(file, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return fail("create file", errno);
    close(fd);

    int failed = 0;
    kind = "directory";
    target = dir;
    failed |= run_all();
    kind = "file";
    target = file;
    failed |= run_all();

    unlink(file);
    rmdir(dir);
    if (failed)
        return 1;
    w("flock-release-ok\n");
    return 0;
}
