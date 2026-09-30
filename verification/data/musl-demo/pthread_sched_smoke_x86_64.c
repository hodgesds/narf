// pthread_create with explicit scheduling attributes must succeed.
//
// Qt's QThread::start(priority) sets PTHREAD_EXPLICIT_SCHED plus a policy and
// priority; glibc's create_thread then applies them to the new thread from
// the parent, right after clone: sched_setscheduler(new_tid, ...) (and
// sched_setaffinity(new_tid, ...) for an affinity attribute). If the kernel
// cannot resolve the just-created tid, pthread_create returns that errno and
// the thread never runs. On NARF this surfaced as ksplashqml's
// "QThread::start: Thread creation error (No such process)" (ESRCH).
//
// Also covers the calls a thread makes on itself and a sibling by tid:
// sched_setscheduler / sched_getscheduler / sched_setparam / sched_getparam /
// sched_setaffinity / sched_getaffinity / setpriority, on a sibling thread's
// tid, which Linux resolves with find_task_by_vpid.
//
// Success token "pthread-sched-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failed;

static void fail(const char *what, int err) {
    printf("pthread-sched-fail: %s (errno %d: %s)\n", what, err, strerror(err));
    fflush(stdout);
    failed = 1;
}

static volatile pid_t child_tid;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int release;

static void *body(void *arg) {
    (void)arg;
    child_tid = (pid_t)syscall(SYS_gettid);
    pthread_mutex_lock(&mtx);
    while (!release)
        pthread_cond_wait(&cv, &mtx);
    pthread_mutex_unlock(&mtx);
    return NULL;
}

static void release_and_join(pthread_t t) {
    pthread_mutex_lock(&mtx);
    release = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mtx);
    pthread_join(t, NULL);
    release = 0;
    child_tid = 0;
}

// Qt's shape: explicit SCHED_OTHER (priority 0) or SCHED_IDLE/BATCH.
static void create_with_policy(int policy, const char *name) {
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setinheritsched(&a, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&a, policy);
    struct sched_param sp = {.sched_priority = 0};
    pthread_attr_setschedparam(&a, &sp);
    pthread_t t;
    int r = pthread_create(&t, &a, body, NULL);
    pthread_attr_destroy(&a);
    if (r != 0) {
        char m[96];
        snprintf(m, sizeof m, "pthread_create with explicit %s", name);
        fail(m, r);
        return;
    }
    while (!child_tid)
        usleep(1000);
    release_and_join(t);
}

static int run_all(void);

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (run_all() != 0)
        return 1;
    // CachyOS runs inside a PID namespace (unshare --pid), where every tid a
    // task names is namespace-local. As root, run the checks again in a child
    // that is PID 1 of a new PID namespace. (The unsharing process itself may
    // no longer create threads: copy_process refuses CLONE_THREAD with EINVAL
    // once pid_ns_for_children differs from the active namespace.)
    if (geteuid() == 0 && unshare(CLONE_NEWPID) == 0) {
        pid_t child = fork();
        if (child == 0)
            _exit(run_all());
        int status = 0;
        waitpid(child, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("pthread-sched-fail: inside a new PID namespace (status %#x)\n", status);
            return 1;
        }
    }
    printf("pthread-sched-ok\n");
    return 0;
}

static int run_all(void) {
    create_with_policy(SCHED_OTHER, "SCHED_OTHER");
    create_with_policy(SCHED_BATCH, "SCHED_BATCH");
    create_with_policy(SCHED_IDLE, "SCHED_IDLE");

    // An affinity attribute: glibc applies it with sched_setaffinity(new_tid).
    // (musl has no pthread_attr_setaffinity_np.)
#ifdef __GLIBC__
    {
        pthread_attr_t a;
        pthread_attr_init(&a);
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(0, &set);
        pthread_attr_setaffinity_np(&a, sizeof set, &set);
        pthread_t t;
        int r = pthread_create(&t, &a, body, NULL);
        pthread_attr_destroy(&a);
        if (r != 0) {
            fail("pthread_create with an affinity attribute", r);
        } else {
            while (!child_tid)
                usleep(1000);
            release_and_join(t);
        }
    }
#endif

    // Sibling-tid calls from the main thread. Raw syscalls: musl's sched_*
    // policy wrappers are ENOSYS stubs by design and never reach the kernel.
    pthread_t t;
    if (pthread_create(&t, NULL, body, NULL) != 0) {
        fail("pthread_create", errno);
        return 1;
    }
    while (!child_tid)
        usleep(1000);
    pid_t tid = child_tid;
    struct sched_param sp = {.sched_priority = 0};
    if (syscall(SYS_sched_setscheduler, tid, SCHED_BATCH, &sp) != 0)
        fail("sched_setscheduler(sibling tid)", errno);
    if (syscall(SYS_sched_getscheduler, tid) != SCHED_BATCH)
        fail("sched_getscheduler(sibling tid) did not read back SCHED_BATCH", errno);
    if (syscall(SYS_sched_setparam, tid, &sp) != 0)
        fail("sched_setparam(sibling tid)", errno);
    if (syscall(SYS_sched_getparam, tid, &sp) != 0)
        fail("sched_getparam(sibling tid)", errno);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(tid, sizeof set, &set) != 0)
        fail("sched_setaffinity(sibling tid)", errno);
    if (sched_getaffinity(tid, sizeof set, &set) != 0)
        fail("sched_getaffinity(sibling tid)", errno);
    if (setpriority(PRIO_PROCESS, tid, 5) != 0)
        fail("setpriority(PRIO_PROCESS, sibling tid)", errno);
    release_and_join(t);

    // A tid that does not exist is ESRCH.
    if (syscall(SYS_sched_getscheduler, 0x3fffffff) != -1 || errno != ESRCH)
        fail("sched_getscheduler(nonexistent tid) is not ESRCH", errno);

    return failed;
}
