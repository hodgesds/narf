// Per-thread nice, as on Linux.
//
// Linux keeps nice in each task_struct (static_prio): setpriority(
// PRIO_PROCESS, who) names ONE thread (who == 0 is the calling thread, any
// other value is a tid via find_task_by_vpid), PRIO_PGRP/PRIO_USER visit
// every thread of every matching process, and a new task inherits the
// FORKING thread's nice (sched_fork). Mesa's util_queue relies on this to
// renice only its workers: setpriority(PRIO_PROCESS, gettid(), 19).
//
// Only raises nice, so it also runs unprivileged on a Linux host.
// Success token "nice-thread-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void w(const char *m) { write(1, m, strlen(m)); }

static int fail(const char *m, int got) {
    char buf[112];
    int n = snprintf(buf, sizeof buf, "nice-thread-fail: %s (got %d, errno %d)\n", m, got, errno);
    write(1, buf, n);
    return 1;
}

static int prio(int which, int who) {
    errno = 0;
    int r = getpriority(which, who);
    return (r == -1 && errno != 0) ? -1000 : r;
}

static pid_t tid(void) { return (pid_t)syscall(SYS_gettid); }

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int stage = 0;
static pid_t worker_tid;
static int worker_err;
static int grandchild_nice = -1000;
static int fork_child_status = -1;

static void *grandchild(void *arg) {
    (void)arg;
    grandchild_nice = prio(PRIO_PROCESS, 0);
    return NULL;
}

static void *worker(void *arg) {
    (void)arg;
    worker_tid = tid();
    if (setpriority(PRIO_PROCESS, worker_tid, 10) != 0)
        worker_err = 1;
    else if (prio(PRIO_PROCESS, 0) != 10)
        worker_err = 2;
    // A thread created by this thread inherits its nice.
    pthread_t g;
    pthread_create(&g, NULL, grandchild, NULL);
    pthread_join(g, NULL);
    // So does a process forked by this thread.
    pid_t pid = fork();
    if (pid == 0)
        _exit(prio(PRIO_PROCESS, 0) == 10 ? 0 : 1);
    int status;
    waitpid(pid, &status, 0);
    fork_child_status = WIFEXITED(status) ? WEXITSTATUS(status) : 2;
    pthread_mutex_lock(&mtx);
    stage = 1;
    pthread_cond_broadcast(&cv);
    while (stage != 2)
        pthread_cond_wait(&cv, &mtx);
    pthread_mutex_unlock(&mtx);
    return NULL;
}

int main(void) {
    int r;
    // Own process group, so PRIO_PGRP below touches only this test and not
    // the shell (and every later test) that launched it.
    if (setpgid(0, 0) != 0)
        return fail("setpgid", -1);
    if ((r = prio(PRIO_PROCESS, 0)) != 0)
        return fail("initial nice is not 0", r);
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_mutex_lock(&mtx);
    while (stage != 1)
        pthread_cond_wait(&cv, &mtx);
    pthread_mutex_unlock(&mtx);

    if (worker_err)
        return fail("worker setpriority(PRIO_PROCESS, gettid(), 10)", worker_err);
    if ((r = prio(PRIO_PROCESS, 0)) != 0)
        return fail("renicing a worker changed the main thread", r);
    if ((r = prio(PRIO_PROCESS, getpid())) != 0)
        return fail("renicing a worker changed the leader (pid)", r);
    if ((r = prio(PRIO_PROCESS, worker_tid)) != 10)
        return fail("getpriority(PRIO_PROCESS, worker tid)", r);
    if (grandchild_nice != 10)
        return fail("thread created by the reniced thread did not inherit", grandchild_nice);
    if (fork_child_status != 0)
        return fail("child forked by the reniced thread did not inherit", fork_child_status);
    // PRIO_PGRP reports the best (lowest) nice of every thread in the group.
    if ((r = prio(PRIO_PGRP, 0)) != 0)
        return fail("getpriority(PRIO_PGRP) not the minimum over threads", r);
    // who == 0 is the calling thread only.
    if (setpriority(PRIO_PROCESS, 0, 5) != 0)
        return fail("setpriority(PRIO_PROCESS, 0, 5)", -1);
    if ((r = prio(PRIO_PROCESS, worker_tid)) != 10)
        return fail("setpriority(0) on main changed the worker", r);
    if ((r = prio(PRIO_PROCESS, 0)) != 5)
        return fail("setpriority(0) did not renice the caller", r);
    // PRIO_PGRP renices every thread of the group.
    if (setpriority(PRIO_PGRP, 0, 12) != 0)
        return fail("setpriority(PRIO_PGRP, 0, 12)", -1);
    if ((r = prio(PRIO_PROCESS, 0)) != 12)
        return fail("PRIO_PGRP set missed the main thread", r);
    if ((r = prio(PRIO_PROCESS, worker_tid)) != 12)
        return fail("PRIO_PGRP set missed the worker thread", r);

    pthread_mutex_lock(&mtx);
    stage = 2;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mtx);
    pthread_join(t, NULL);
    w("nice-thread-ok\n");
    return 0;
}
