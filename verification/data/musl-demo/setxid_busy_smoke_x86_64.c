// set*id() broadcast while the other threads are BUSY, one activity each.
//
// setxid_threads_smoke covers threads parked in a blocking wait. This one
// keeps each worker running a single class of work while the main thread
// calls seteuid() in a loop, so a hang names the kernel path that loses
// the SIGSETXID (glibc) / __synccall (musl) signal:
//   fileio    open(O_CREAT)/flock/write/rename/close, Mesa's cache write
//   condwait  pthread_cond_timedwait with a short timeout
//   forking   fork + waitpid
//   spin      pure user-space compute (delivery on interrupt return)
//
// Every case runs in its own child with a timeout (SIGALRM reports the stuck
// case), both right after the workers are created and after they settle.
// Success token "setxid-busy-ok".
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NWORKER 3
#define CALLS 400

static void w(const char *m) { write(1, m, strlen(m)); }

static volatile int stop;
static const char *volatile phase = "start";
static volatile int calls_done;

static void on_alarm(int sig) {
    (void)sig;
    char buf[96];
    int n = snprintf(buf, sizeof buf, "setxid-busy-fail: hung in case %s after %d seteuid calls\n",
                     phase, calls_done);
    write(1, buf, n);
    _exit(1);
}

static void *fileio(void *arg) {
    int id = (int)(long)arg;
    char tmp[80], fin[64];
    snprintf(fin, sizeof fin, "/tmp/setxid-busy.%d", id);
    snprintf(tmp, sizeof tmp, "%s.tmp", fin);
    char payload[256];
    memset(payload, 'a' + id, sizeof payload);
    while (!stop) {
        int fd = open(tmp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
        if (fd < 0)
            continue;
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            (void)write(fd, payload, sizeof payload);
            (void)rename(tmp, fin);
        }
        close(fd);
    }
    return NULL;
}

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static void *condwait(void *arg) {
    (void)arg;
    while (!stop) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 200 * 1000;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&mtx);
        pthread_cond_timedwait(&cv, &mtx, &ts);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

static void *forking(void *arg) {
    (void)arg;
    while (!stop) {
        pid_t pid = fork();
        if (pid == 0)
            _exit(0);
        if (pid > 0)
            waitpid(pid, NULL, 0);
    }
    return NULL;
}

static volatile unsigned long spin_count;
static void *spin(void *arg) {
    (void)arg;
    while (!stop)
        spin_count++;
    return NULL;
}

static int run_case(const char *name, void *(*fn)(void *), int settle_ms) {
    phase = name;
    stop = 0;
    calls_done = 0;
    pthread_t t[NWORKER];
    for (long i = 0; i < NWORKER; i++)
        if (pthread_create(&t[i], NULL, fn, (void *)i) != 0) {
            w("setxid-busy-fail: pthread_create\n");
            return 1;
        }
    if (settle_ms)
        usleep(settle_ms * 1000);
    for (int i = 0; i < CALLS; i++) {
        if (seteuid(geteuid()) != 0) {
            w("setxid-busy-fail: seteuid\n");
            return 1;
        }
        calls_done = i + 1;
    }
    stop = 1;
    for (int i = 0; i < NWORKER; i++)
        pthread_join(t[i], NULL);
    return 0;
}

// Each case runs in its own child with its own timeout, so one hang cannot
// hide the result of the others.
static int in_child(const char *name, void *(*fn)(void *), int settle_ms) {
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGALRM, on_alarm);
        alarm(20);
        _exit(run_case(name, fn, settle_ms));
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    int failed = 0;
    // Threads still starting up when seteuid() runs, then the same work
    // after the threads have settled.
    failed |= in_child("spin", spin, 0);
    failed |= in_child("spin-settled", spin, 50);
    failed |= in_child("condwait", condwait, 0);
    failed |= in_child("condwait-settled", condwait, 50);
    failed |= in_child("fileio", fileio, 0);
    failed |= in_child("fileio-settled", fileio, 50);
    failed |= in_child("forking", forking, 0);
    failed |= in_child("forking-settled", forking, 50);
    if (failed)
        return 1;
    w("setxid-busy-ok\n");
    return 0;
}
