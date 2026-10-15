// /proc/<tid> for a non-leader thread, checked against Linux.
//
// Linux resolves /proc/<n> for ANY thread id, not only thread-group ids:
// readdir lists only the group leaders, but a lookup by a sibling's tid finds
// a directory with the group's files, whose stat and status describe that
// thread (`proc_pid_lookup` -> `proc_pid_instantiate(task)`; `do_task_stat`
// prints `task_pid_nr_ns(task)`, `proc_pid_status` prints Tgid and Pid
// separately). Crash reporters and debuggers are handed a crashing THREAD's
// id and open /proc/<tid>/stat, /proc/<tid>/maps and /proc/<tid>/mem; on NARF
// every one of them was ENOENT (Chromium's crashpad: "open
// /proc/<pid>/stat: No such file or directory").
//
// Success token "proctid-ok".
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("proctid-fail: " __VA_ARGS__);                              \
            printf(" (errno=%d)\n", errno);                                    \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static int slurp(const char *path, char *buf, int len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, len - 1);
    close(fd);
    if (n >= 0) buf[n] = 0;
    return n;
}

static long field(const char *buf, const char *key) {
    const char *p = strstr(buf, key);
    return p ? strtol(p + strlen(key), 0, 10) : -1;
}

static volatile pid_t ttid;
static int pipefd[2];
static void *thr(void *a) {
    (void)a;
    ttid = syscall(SYS_gettid);
    char c;
    read(pipefd[0], &c, 1);
    return 0;
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    pipe(pipefd);
    pthread_t t;
    pthread_create(&t, 0, thr, 0);
    while (!ttid) usleep(1000);
    usleep(200000);
    pid_t pid = getpid();
    char path[64], buf[4096];

    snprintf(path, sizeof path, "/proc/%d/stat", ttid);
    CHECK(slurp(path, buf, sizeof buf) > 0, "open %s", path);
    CHECK(atoi(buf) == ttid, "%s pid field %d, want the tid %d", path, atoi(buf), ttid);
    char *rp = strrchr(buf, ')');
    CHECK(rp && rp[2] == 'S', "%s state %c, want S (blocked in read)", path, rp ? rp[2] : '?');

    snprintf(path, sizeof path, "/proc/%d/status", ttid);
    CHECK(slurp(path, buf, sizeof buf) > 0, "open %s", path);
    CHECK(field(buf, "\nTgid:\t") == pid, "%s Tgid %ld, want %d", path, field(buf, "\nTgid:\t"), pid);
    CHECK(field(buf, "\nPid:\t") == ttid, "%s Pid %ld, want %d", path, field(buf, "\nPid:\t"), ttid);

    snprintf(path, sizeof path, "/proc/%d/maps", ttid);
    CHECK(slurp(path, buf, sizeof buf) > 0, "open %s", path);
    snprintf(path, sizeof path, "/proc/%d/comm", ttid);
    CHECK(slurp(path, buf, sizeof buf) > 0, "open %s", path);

    // Hidden from readdir: only thread-group leaders are listed.
    DIR *d = opendir("/proc");
    struct dirent *e;
    int listed = 0;
    while (d && (e = readdir(d)))
        if (atoi(e->d_name) == ttid) listed = 1;
    if (d) closedir(d);
    CHECK(!listed, "/proc readdir lists the non-leader tid %d", ttid);

    write(pipefd[1], "x", 1);
    pthread_join(t, 0);
    snprintf(path, sizeof path, "/proc/%d/stat", ttid);
    // pthread_join returns at the CLONE_CHILD_CLEARTID wake, which Linux
    // issues from mm_release, before release_task unhashes the thread's pid;
    // the directory goes away shortly after, not at the join itself.
    int gone = 0;
    for (int i = 0; i < 200 && !gone; i++) {
        errno = 0;
        int fd = open(path, O_RDONLY);
        if (fd < 0 && errno == ENOENT)
            gone = 1;
        else {
            if (fd >= 0) close(fd);
            usleep(10000);
        }
    }
    CHECK(gone, "%s still opens 2s after the thread exited", path);

    if (fails == 0) printf("proctid-ok\n");
    return fails != 0;
}
