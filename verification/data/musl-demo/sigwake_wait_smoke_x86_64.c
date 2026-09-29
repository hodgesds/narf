// A caught signal must wake the thread parked in a blocking wait, and
// SA_RESTART must re-run the wait so it sees what the handler changed.
//
// fish's shape: worker threads block every signal, the main thread spawns a
// child (glibc posix_spawn = clone3(CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND))
// and parks in sem_wait (glibc: FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME, no
// timeout). The child's SIGCHLD runs the handler on the main thread, the
// handler sem_post()s, and the restarted futex wait returns EAGAIN because the
// word changed. If the wake or the restart is lost, fish sleeps until Ctrl-C.
//
//   waiters: sem_wait, FUTEX_WAIT_BITSET|CLOCK_REALTIME, FUTEX_WAIT, poll,
//            read on a pipe
//   sources: posix_spawn child exit (SIGCHLD), fork child exit (SIGCHLD),
//            kill(getpid(), SIGUSR1) from a signal-blocking worker
//   timing:  the signal arrives before the wait parks or while it is parked
//
// Each case runs in its own child with a timeout, so a lost wake is a named
// failure: "sigwake-wait-fail: case=sem_wait/spawn round=3".
// Success token "sigwake-wait-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUNDS 20

// <linux/futex.h> values (musl ships no kernel headers).
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define FUTEX_WAIT_BITSET_PRIVATE (9 | 128)
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_BITSET_MATCH_ANY 0xffffffff

extern char **environ;

static void w(const char *m) { write(1, m, strlen(m)); }

enum waiter { W_SEM, W_FUTEX_BITSET_RT, W_FUTEX, W_POLL, W_READ, W_COUNT };
enum source { S_SPAWN, S_FORK, S_KILL, S_COUNT };
static const char *waiter_name[] = {"sem_wait", "futex_bitset_rt", "futex", "poll", "read"};
static const char *source_name[] = {"spawn", "fork", "kill"};

static char self_path[PATH_MAX];
static const char *volatile cur_case = "?";
static volatile int cur_round;

static enum waiter g_waiter;
static sem_t sem;
static volatile int futex_word;
static int wake_pipe[2];
static volatile pid_t handler_tid;

static pid_t gettid_(void) { return (pid_t)syscall(SYS_gettid); }

static void on_alarm(int sig) {
    (void)sig;
    char buf[128];
    int n = snprintf(buf, sizeof buf, "sigwake-wait-fail: case=%s round=%d (timed out)\n", cur_case,
                     cur_round);
    write(1, buf, n);
    _exit(1);
}

// The handler makes the wait's condition true, as fish's topic monitor does.
static void on_signal(int sig) {
    (void)sig;
    int saved = errno;
    handler_tid = gettid_();
    switch (g_waiter) {
    case W_SEM:
        sem_post(&sem);
        break;
    case W_FUTEX_BITSET_RT:
    case W_FUTEX:
        futex_word = 1;
        syscall(SYS_futex, &futex_word, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
        break;
    case W_POLL:
    case W_READ:
        (void)write(wake_pipe[1], "x", 1);
        break;
    default:
        break;
    }
    errno = saved;
}

// Returns 0 once the handler's effect is observed.
static int wait_once(enum waiter wt) {
    switch (wt) {
    case W_SEM:
        while (sem_wait(&sem) != 0)
            if (errno != EINTR)
                return -1;
        return 0;
    case W_FUTEX_BITSET_RT:
        while (futex_word == 0)
            syscall(SYS_futex, &futex_word, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME, 0, NULL,
                    NULL, FUTEX_BITSET_MATCH_ANY);
        return 0;
    case W_FUTEX:
        while (futex_word == 0)
            syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
        return 0;
    case W_POLL: {
        struct pollfd pfd = {wake_pipe[0], POLLIN, 0};
        for (;;) {
            int r = poll(&pfd, 1, -1);
            if (r == 1)
                break;
            if (r < 0 && errno != EINTR)
                return -1;
        }
        char c;
        (void)read(wake_pipe[0], &c, 1);
        return 0;
    }
    case W_READ: {
        char c;
        for (;;) {
            ssize_t r = read(wake_pipe[0], &c, 1);
            if (r == 1)
                return 0;
            if (r < 0 && errno != EINTR)
                return -1;
        }
    }
    default:
        return -1;
    }
}

// Signal-blocking worker threads, like fish's iothreads.
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int workers_stop;
static void *idle_worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&mtx);
    while (!workers_stop)
        pthread_cond_wait(&cv, &mtx);
    pthread_mutex_unlock(&mtx);
    return NULL;
}

static int kill_delay_us;
static void *kill_worker(void *arg) {
    (void)arg;
    if (kill_delay_us)
        usleep(kill_delay_us);
    kill(getpid(), SIGUSR1);
    return NULL;
}

static void block_all_in_this_thread(sigset_t *old) {
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, old);
}

static int run_case(enum waiter wt, enum source src) {
    g_waiter = wt;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigaction(src == S_KILL ? SIGUSR1 : SIGCHLD, &sa, NULL);
    if (sem_init(&sem, 0, 0) != 0 || pipe2(wake_pipe, O_CLOEXEC) != 0)
        return 1;

    // Threads created with every signal blocked keep that mask.
    sigset_t old;
    block_all_in_this_thread(&old);
    pthread_t idle[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&idle[i], NULL, idle_worker, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);

    for (int r = 0; r < ROUNDS; r++) {
        cur_round = r;
        futex_word = 0;
        handler_tid = 0;
        int delay_ms = r % 2 ? 20 : 0;
        pid_t child = -1;
        pthread_t killer;
        if (src == S_SPAWN) {
            char ms[16];
            snprintf(ms, sizeof ms, "%d", delay_ms);
            char *argv[] = {self_path, "--exit-after-ms", ms, NULL};
            if (posix_spawn(&child, self_path, NULL, NULL, argv, environ) != 0)
                return 1;
        } else if (src == S_FORK) {
            child = fork();
            if (child == 0) {
                if (delay_ms)
                    usleep(delay_ms * 1000);
                _exit(0);
            }
        } else {
            kill_delay_us = delay_ms * 1000;
            block_all_in_this_thread(&old);
            pthread_create(&killer, NULL, kill_worker, NULL);
            pthread_sigmask(SIG_SETMASK, &old, NULL);
        }
        if (wait_once(wt) != 0)
            return 1;
        if (handler_tid != gettid_()) {
            char buf[128];
            int n = snprintf(buf, sizeof buf,
                             "sigwake-wait-fail: case=%s round=%d handler ran on a blocking thread\n",
                             cur_case, r);
            write(1, buf, n);
            return 1;
        }
        if (child > 0)
            waitpid(child, NULL, 0);
        if (src == S_KILL)
            pthread_join(killer, NULL);
    }

    pthread_mutex_lock(&mtx);
    workers_stop = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mtx);
    for (int i = 0; i < 2; i++)
        pthread_join(idle[i], NULL);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--exit-after-ms") == 0) {
        int ms = atoi(argv[2]);
        if (ms)
            usleep(ms * 1000);
        return 0;
    }
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof self_path - 1);
    if (n > 0)
        self_path[n] = 0;
    else
        snprintf(self_path, sizeof self_path, "%s", argv[0]);

    int failed = 0;
    for (int wt = 0; wt < W_COUNT; wt++)
        for (int src = 0; src < S_COUNT; src++) {
            char name[48];
            snprintf(name, sizeof name, "%s/%s", waiter_name[wt], source_name[src]);
            pid_t pid = fork();
            if (pid == 0) {
                cur_case = name;
                signal(SIGALRM, on_alarm);
                alarm(10);
                if (run_case(wt, src) != 0) {
                    char buf[96];
                    int k = snprintf(buf, sizeof buf, "sigwake-wait-fail: case=%s round=%d\n", name,
                                     cur_round);
                    write(1, buf, k);
                    _exit(1);
                }
                _exit(0);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
                if (!WIFEXITED(status)) {
                    char buf[96];
                    int k = snprintf(buf, sizeof buf, "sigwake-wait-fail: case=%s died (status %#x)\n",
                                     name, status);
                    write(1, buf, k);
                }
                failed = 1;
            }
        }
    if (failed)
        return 1;
    w("sigwake-wait-ok\n");
    return 0;
}
