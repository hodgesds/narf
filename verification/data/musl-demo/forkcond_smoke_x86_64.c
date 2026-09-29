// fork() racing condvar handoffs to worker threads doing file I/O.
//
// Shape of the Xwayland/Plasma wedge on CachyOS: Xwayland's main thread
// queues shader-cache writes to Mesa's `disk$0` worker (a condvar-driven
// util_queue), and meanwhile fork()s xkbcomp for each keymap compile. The
// worker's cache write is open(<hash>.tmp, O_WRONLY|O_CREAT|O_CLOEXEC) ->
// flock(LOCK_EX|LOCK_NB) -> write -> rename. On NARF the worker was left
// asleep in its condvar wait with the handoff lost: Xwayland's main thread
// waited on the job forever, so kwin (blocked in a synchronous X11 round
// trip) stopped serving Wayland and plasmashell was killed by systemd's
// start timeout in a loop.
//
// This smoke replays that shape: NWORKER threads pin themselves to every
// CPU and drop to nice 19 by their own tid (exactly as Mesa's disk-cache
// util_queue does), wait for jobs on a condvar and perform the same file
// sequence; the main thread queues a
// job, forks a child that _exits, reaps it, and waits for the job to
// complete, ROUNDS times. A correct kernel completes every job.
// SIGALRM turns a stranded handoff into a failure token instead of a hang.
//
// Success token "forkcond-ok".
//
// Build: see REGEN_forkcond_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define NWORKER 3
#define ROUNDS 200

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t has_job = PTHREAD_COND_INITIALIZER;
static pthread_cond_t job_done = PTHREAD_COND_INITIALIZER;
static int queued = 0;    // jobs handed to the workers so far
static int taken = 0;     // jobs a worker has claimed
static int completed = 0; // jobs finished
static int io_errors = 0;
static int affinity_errors = 0;
static int priority_errors = 0;
static volatile int progress = 0;

static void on_alarm(int sig) {
    (void)sig;
    char buf[96];
    int n = snprintf(buf, sizeof buf, "forkcond-fail: stranded at round %d (taken=%d done=%d)\n",
                     progress, taken, completed);
    write(1, buf, n);
    _exit(1);
}

static int cache_write(int job) {
    char tmp[80], final_path[64];
    snprintf(final_path, sizeof final_path, "/tmp/forkcond.%d", job % 16);
    snprintf(tmp, sizeof tmp, "%s.tmp", final_path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;
    int rc = 0;
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        char payload[512];
        memset(payload, 'a' + job % 26, sizeof payload);
        if (write(fd, payload, sizeof payload) != (ssize_t)sizeof payload)
            rc = -1;
        if (rename(tmp, final_path) != 0)
            rc = -1;
    }
    close(fd);
    return rc;
}

static void *worker(void *arg) {
    (void)arg;
    // Mesa's disk-cache util_queue: UTIL_QUEUE_INIT_SET_FULL_THREAD_AFFINITY
    // and UTIL_QUEUE_INIT_USE_MINIMUM_PRIORITY, both keyed by the thread's
    // own tid (src/util/u_queue.c).
    pid_t tid = (pid_t)syscall(SYS_gettid);
    cpu_set_t all;
    CPU_ZERO(&all);
    for (int c = 0; c < CPU_SETSIZE; c++)
        CPU_SET(c, &all);
    if (sched_setaffinity(tid, sizeof all, &all) != 0) {
        pthread_mutex_lock(&mtx);
        affinity_errors++;
        pthread_mutex_unlock(&mtx);
    }
    if (setpriority(PRIO_PROCESS, tid, 19) != 0) {
        pthread_mutex_lock(&mtx);
        priority_errors++;
        pthread_mutex_unlock(&mtx);
    }
    for (;;) {
        pthread_mutex_lock(&mtx);
        while (taken == queued)
            pthread_cond_wait(&has_job, &mtx);
        int job = taken++;
        pthread_mutex_unlock(&mtx);

        int rc = cache_write(job);

        pthread_mutex_lock(&mtx);
        if (rc != 0)
            io_errors++;
        completed++;
        pthread_cond_signal(&job_done);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

int main(void) {
    signal(SIGALRM, on_alarm);
    alarm(60);
    pthread_t t[NWORKER];
    for (int i = 0; i < NWORKER; i++) {
        if (pthread_create(&t[i], NULL, worker, NULL) != 0) {
            w("forkcond-fail: pthread_create\n");
            return 1;
        }
    }
    for (int r = 0; r < ROUNDS; r++) {
        progress = r;
        pthread_mutex_lock(&mtx);
        queued++;
        pthread_cond_signal(&has_job);
        pthread_mutex_unlock(&mtx);

        pid_t pid = fork();
        if (pid == 0)
            _exit(0);
        if (pid < 0) {
            w("forkcond-fail: fork\n");
            return 1;
        }
        int status = 0;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
            w("forkcond-fail: waitpid\n");
            return 1;
        }

        pthread_mutex_lock(&mtx);
        while (completed < queued)
            pthread_cond_wait(&job_done, &mtx);
        pthread_mutex_unlock(&mtx);
    }
    if (affinity_errors != 0 || priority_errors != 0) {
        char buf[96];
        int n = snprintf(buf, sizeof buf, "forkcond-fail: sched_setaffinity errs=%d setpriority errs=%d\n",
                         affinity_errors, priority_errors);
        write(1, buf, n);
        return 1;
    }
    if (io_errors != 0) {
        char buf[64];
        int n = snprintf(buf, sizeof buf, "forkcond-fail: %d cache writes failed\n", io_errors);
        write(1, buf, n);
        return 1;
    }
    w("forkcond-ok\n");
    return 0;
}
