// /proc state letters, checked against Linux (`task_state_array`).
//
// A task blocked in a syscall is 'S' (TASK_INTERRUPTIBLE) in /proc/<pid>/stat
// field 3 and "State:\tS (sleeping)" in /proc/<pid>/status; a job-control
// stopped task is 'T'; the task reading its own stat is running ('R').
// NARF reported 'R' for every sleeping task, so `ps`/`top` showed an idle
// system as all-running.
//
// Success token "procstate-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("procstate-fail: " __VA_ARGS__);                            \
            printf("\n");                                                      \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static char stat_state(const char *path) {
    char buf[512] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) return '?';
    int n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return '?';
    char *rp = strrchr(buf, ')');
    return rp && rp[1] == ' ' ? rp[2] : '?';
}

static int status_has(const char *path, const char *want) {
    char buf[4096] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    int n = read(fd, buf, sizeof buf - 1);
    close(fd);
    return n > 0 && strstr(buf, want) != NULL;
}

static int pipefd[2];
static volatile pid_t reader_tid;
static void *reader(void *a) {
    (void)a;
    reader_tid = syscall(SYS_gettid);
    char c;
    read(pipefd[0], &c, 1);
    return 0;
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    char path[96];
    CHECK(stat_state("/proc/self/stat") == 'R', "own stat state %c, want R", stat_state("/proc/self/stat"));

    // A thread blocked in read(2).
    pipe(pipefd);
    pthread_t t;
    pthread_create(&t, 0, reader, 0);
    while (!reader_tid) usleep(1000);
    usleep(200000);
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", reader_tid);
    CHECK(stat_state(path) == 'S', "blocked thread state %c, want S", stat_state(path));
    write(pipefd[1], "x", 1);
    pthread_join(t, 0);

    // A child blocked in pause(), then stopped.
    pid_t c = fork();
    if (c == 0) {
        for (;;) pause();
    }
    usleep(200000);
    snprintf(path, sizeof path, "/proc/%d/stat", c);
    CHECK(stat_state(path) == 'S', "paused child state %c, want S", stat_state(path));
    snprintf(path, sizeof path, "/proc/%d/status", c);
    CHECK(status_has(path, "State:\tS (sleeping)"), "paused child status not S (sleeping)");
    kill(c, SIGSTOP);
    usleep(200000);
    snprintf(path, sizeof path, "/proc/%d/stat", c);
    CHECK(stat_state(path) == 'T', "stopped child state %c, want T", stat_state(path));
    kill(c, SIGKILL);
    waitpid(c, 0, 0);

    if (fails == 0) printf("procstate-ok\n");
    return fails != 0;
}
