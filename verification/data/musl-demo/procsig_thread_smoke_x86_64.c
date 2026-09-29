// Process-directed signals in a multithreaded process (Linux shared pending).
//
// Linux keeps two pending sets: each thread's private `task->pending` and
// the thread group's `signal->shared_pending`. Thread-directed sends
// (tkill/tgkill/rt_tgsigqueueinfo, synchronous faults) use the private set.
// Process-directed sends (kill(pid), sigqueue(pid), a child's SIGCHLD,
// SIGIO/itimer/POSIX-timer to a process) use the shared set, and
// complete_signal() wakes ANY thread that does not block the signal.
// dequeue_signal() drains private first, then shared; sigpending() reports
// both; sigwait/signalfd in any thread can take a shared signal; a stop
// signal stops the whole group and SIGCONT resumes it; a fatal default
// action kills the whole group.
//
// fish depends on this: its worker threads block every signal while the
// main thread waits on a monitor woken from the SIGCHLD/SIGINT handlers, so a
// SIGCHLD left on the forking worker stalls it until Ctrl-C.
//
// Each case runs in its own child with a timeout, so one failure cannot
// hide another. Success token "procsig-thread-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void w(const char *m) { write(1, m, strlen(m)); }

static const char *volatile cur_case = "?";
static int fail(const char *what) {
    char buf[128];
    int n = snprintf(buf, sizeof buf, "procsig-thread-fail: %s: %s\n", cur_case, what);
    write(1, buf, n);
    return 1;
}

static void on_alarm(int sig) {
    (void)sig;
    fail("timed out");
    _exit(1);
}

// ── Handler plumbing: the handler records which thread ran it. ────────
static int selfpipe[2];
static volatile pid_t handler_tid;
static void handler(int sig) {
    char c = (char)sig;
    handler_tid = gettid();
    int saved = errno;
    (void)write(selfpipe[1], &c, 1);
    errno = saved;
}
static int await_handler(int sig, int ms) {
    struct pollfd pfd = {selfpipe[0], POLLIN, 0};
    for (;;) {
        int r = poll(&pfd, 1, ms);
        if (r < 0 && errno == EINTR)
            continue;
        if (r != 1)
            return 0;
        char c;
        while (read(selfpipe[0], &c, 1) == 1)
            if (c == sig)
                return 1;
    }
}
static void install(int sig) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    sigaction(sig, &sa, NULL);
}
static void block(int sig) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
}
static void unblock(int sig) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);
}
static void block_all(void) {
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
}

// A worker that parks until `release` is set.
static volatile int release;
static void *parked(void *arg) {
    (void)arg;
    while (!release)
        usleep(1000);
    return NULL;
}

// ── Cases ───────────────────────────────────────────────────────────

static void *fork_worker(void *arg) {
    (void)arg;
    block_all();
    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    return (void *)(long)pid;
}
// A child forked by a signal-blocking worker: its SIGCHLD must reach the
// unblocked main thread.
static int case_sigchld_worker_fork(void) {
    install(SIGCHLD);
    pthread_t t;
    void *ret;
    pthread_create(&t, NULL, fork_worker, NULL);
    pthread_join(t, &ret);
    if (!await_handler(SIGCHLD, 2000))
        return fail("handler never ran");
    if (handler_tid != gettid())
        return fail("handler ran on a thread that blocks SIGCHLD");
    waitpid((pid_t)(long)ret, NULL, 0);
    return 0;
}

static void *kill_worker(void *arg) {
    (void)arg;
    block_all();
    kill(getpid(), SIGUSR1);
    return NULL;
}
// kill(getpid()) sent by a blocking worker must reach the unblocked main.
static int case_kill_from_worker(void) {
    install(SIGUSR1);
    pthread_t t;
    pthread_create(&t, NULL, kill_worker, NULL);
    pthread_join(t, NULL);
    if (!await_handler(SIGUSR1, 2000))
        return fail("handler never ran");
    if (handler_tid != gettid())
        return fail("handler ran on a thread that blocks SIGUSR1");
    return 0;
}

// Main blocks the signal, a worker does not: the worker must take it.
static int case_main_blocks(void) {
    install(SIGUSR2);
    pthread_t t;
    pthread_create(&t, NULL, parked, NULL);
    usleep(20000);
    block(SIGUSR2);
    kill(getpid(), SIGUSR2);
    int got = await_handler(SIGUSR2, 2000);
    release = 1;
    pthread_join(t, NULL);
    if (!got)
        return fail("no unblocked thread took SIGUSR2");
    if (handler_tid == gettid())
        return fail("handler ran on the thread that blocks it");
    return 0;
}

static volatile int waited_sig;
static volatile int waited_code = 99;
static void *sigwait_worker(void *arg) {
    (void)arg;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    siginfo_t si;
    struct timespec ts = {2, 0};
    int r = sigtimedwait(&s, &si, &ts);
    if (r == SIGUSR1) {
        waited_sig = r;
        waited_code = si.si_code;
    }
    return NULL;
}
// Every thread blocks SIGUSR1; a dedicated thread sigwaits for it.
static int case_sigwait_dedicated(void) {
    block(SIGUSR1); // inherited by the worker
    pthread_t t;
    pthread_create(&t, NULL, sigwait_worker, NULL);
    usleep(20000);
    kill(getpid(), SIGUSR1);
    pthread_join(t, NULL);
    if (waited_sig != SIGUSR1)
        return fail("sigtimedwait in another thread never got the process signal");
    if (waited_code != SI_USER)
        return fail("process-directed kill should carry SI_USER");
    return 0;
}

static volatile int worker_pending_usr2 = -1;
static volatile int worker_pending_usr1 = -1;
static volatile int check_now;
static void *pending_worker(void *arg) {
    (void)arg;
    while (!check_now)
        usleep(1000);
    sigset_t p;
    sigpending(&p);
    worker_pending_usr2 = sigismember(&p, SIGUSR2);
    worker_pending_usr1 = sigismember(&p, SIGUSR1);
    return NULL;
}
// A pending process-directed signal is visible to every thread; a
// thread-directed one only to its target.
static int case_sigpending_union(void) {
    block(SIGUSR1);
    block(SIGUSR2);
    pthread_t t;
    pthread_create(&t, NULL, pending_worker, NULL);
    kill(getpid(), SIGUSR2);
    syscall(SYS_tgkill, getpid(), gettid(), SIGUSR1);
    check_now = 1;
    pthread_join(t, NULL);
    sigset_t mine;
    sigpending(&mine);
    if (!sigismember(&mine, SIGUSR2))
        return fail("main's sigpending misses the process-directed SIGUSR2");
    if (!sigismember(&mine, SIGUSR1))
        return fail("main's sigpending misses its own tgkill SIGUSR1");
    if (worker_pending_usr2 != 1)
        return fail("worker's sigpending misses the process-directed SIGUSR2");
    if (worker_pending_usr1 != 0)
        return fail("worker's sigpending shows main's thread-directed SIGUSR1");
    return 0;
}

static volatile int sfd_got;
static void *signalfd_worker(void *arg) {
    int fd = (int)(long)arg;
    struct pollfd pfd = {fd, POLLIN, 0};
    if (poll(&pfd, 1, 2000) == 1) {
        struct signalfd_siginfo si;
        if (read(fd, &si, sizeof si) == sizeof si)
            sfd_got = (int)si.ssi_signo;
    }
    return NULL;
}
// A signalfd read in another thread consumes a process-directed signal.
static int case_signalfd_other_thread(void) {
    block(SIGUSR2);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    int fd = signalfd(-1, &s, SFD_CLOEXEC);
    if (fd < 0)
        return fail("signalfd");
    pthread_t t;
    pthread_create(&t, NULL, signalfd_worker, (void *)(long)fd);
    usleep(20000);
    kill(getpid(), SIGUSR2);
    pthread_join(t, NULL);
    if (sfd_got != SIGUSR2)
        return fail("signalfd in a worker never read the process signal");
    sigset_t p;
    sigpending(&p);
    if (sigismember(&p, SIGUSR2))
        return fail("signal still pending after a signalfd read consumed it");
    return 0;
}

static volatile int unblock_now;
static void *unblocker(void *arg) {
    (void)arg;
    while (!unblock_now)
        usleep(1000);
    unblock(SIGUSR1);
    usleep(200000);
    return NULL;
}
// A signal pending while every thread blocks it goes to the first thread
// that unblocks it.
static int case_unblock_takes_shared(void) {
    install(SIGUSR1);
    block(SIGUSR1);
    pthread_t t;
    pthread_create(&t, NULL, unblocker, NULL);
    kill(getpid(), SIGUSR1);
    unblock_now = 1;
    int got = await_handler(SIGUSR1, 2000);
    pthread_join(t, NULL);
    if (!got)
        return fail("the unblocking thread never took the pending signal");
    if (handler_tid == gettid())
        return fail("handler ran on the thread that still blocks it");
    return 0;
}

static volatile int suspended_woke;
static void *suspender(void *arg) {
    (void)arg;
    sigset_t empty;
    sigemptyset(&empty);
    sigsuspend(&empty);
    suspended_woke = 1;
    return NULL;
}
// A worker in sigsuspend takes a process-directed signal.
static int case_sigsuspend_worker(void) {
    install(SIGUSR2);
    block(SIGUSR2); // main and (inherited) worker block it outside sigsuspend
    pthread_t t;
    pthread_create(&t, NULL, suspender, NULL);
    usleep(50000);
    kill(getpid(), SIGUSR2);
    int got = await_handler(SIGUSR2, 2000);
    pthread_join(t, NULL);
    if (!got || !suspended_woke)
        return fail("sigsuspend in a worker was not woken by the process signal");
    return 0;
}

static volatile int rt_order_ok = -1;
static void *rt_worker(void *arg) {
    (void)arg;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGRTMIN);
    int ok = 1;
    for (int i = 1; i <= 5; i++) {
        siginfo_t si;
        struct timespec ts = {2, 0};
        if (sigtimedwait(&s, &si, &ts) != SIGRTMIN || si.si_value.sival_int != i)
            ok = 0;
    }
    rt_order_ok = ok;
    return NULL;
}
// Queued RT signals sent to the process are dequeued in order by any thread.
static int case_rt_queue_order(void) {
    block(SIGRTMIN);
    for (int i = 1; i <= 5; i++) {
        union sigval v = {.sival_int = i};
        if (sigqueue(getpid(), SIGRTMIN, v) != 0)
            return fail("sigqueue");
    }
    pthread_t t;
    pthread_create(&t, NULL, rt_worker, NULL);
    pthread_join(t, NULL);
    if (rt_order_ok != 1)
        return fail("worker did not dequeue the queued SIGRTMIN payloads 1..5 in order");
    return 0;
}

// A fatal default-action signal kills the whole process even though the
// leader blocks it, because another thread does not.
static int case_fatal_group(void) {
    pid_t pid = fork();
    if (pid == 0) {
        block(SIGTERM);
        signal(SIGTERM, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        pthread_t t;
        pthread_sigmask(SIG_SETMASK, &none, NULL); // worker starts unblocked
        pthread_create(&t, NULL, parked, NULL);
        block(SIGTERM);
        for (;;)
            pause();
    }
    usleep(100000);
    kill(pid, SIGTERM);
    int status = 0;
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (int i = 0; i < 100; i++) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM)
                return 0;
            return fail("process exited, but not by SIGTERM");
        }
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return fail("SIGTERM with an unblocked worker did not kill the group");
}

// SIGSTOP stops every thread of the process; SIGCONT resumes every thread.
static volatile unsigned long *counters;
static void *counting(void *arg) {
    long i = (long)arg;
    for (;;)
        counters[i]++;
    return NULL;
}
static int case_group_stop(void) {
    counters = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (counters == MAP_FAILED)
        return fail("mmap");
    pid_t pid = fork();
    if (pid == 0) {
        pthread_t t[3];
        for (long i = 1; i <= 3; i++)
            pthread_create(&t[i - 1], NULL, counting, (void *)i);
        counting((void *)0);
    }
    usleep(100000);
    kill(pid, SIGSTOP);
    int status;
    if (waitpid(pid, &status, WUNTRACED) != pid || !WIFSTOPPED(status)) {
        kill(pid, SIGKILL);
        return fail("waitpid(WUNTRACED) did not report the stop");
    }
    usleep(50000);
    unsigned long a[4], b[4];
    for (int i = 0; i < 4; i++)
        a[i] = counters[i];
    usleep(100000);
    for (int i = 0; i < 4; i++)
        b[i] = counters[i];
    int moved = 0;
    for (int i = 0; i < 4; i++)
        moved |= (a[i] != b[i]) << i;
    kill(pid, SIGCONT);
    usleep(100000);
    unsigned long c[4];
    for (int i = 0; i < 4; i++)
        c[i] = counters[i];
    int resumed = 1;
    for (int i = 0; i < 4; i++)
        resumed &= c[i] != b[i];
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    if (moved) {
        char buf[64];
        snprintf(buf, sizeof buf, "threads kept running while stopped (mask %#x)", moved);
        return fail(buf);
    }
    if (!resumed)
        return fail("not every thread resumed after SIGCONT");
    return 0;
}

// ── Driver ──────────────────────────────────────────────────────────

static int run(const char *name, int (*fn)(void)) {
    pid_t pid = fork();
    if (pid == 0) {
        cur_case = name;
        signal(SIGALRM, on_alarm);
        alarm(10);
        if (pipe2(selfpipe, O_CLOEXEC | O_NONBLOCK) != 0)
            _exit(fail("pipe2"));
        _exit(fn());
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;
    if (!WIFEXITED(status)) {
        cur_case = name;
        fail("case process died");
    }
    return 1;
}

int main(void) {
    int failed = 0;
    failed |= run("sigchld-worker-fork", case_sigchld_worker_fork);
    failed |= run("kill-from-worker", case_kill_from_worker);
    failed |= run("main-blocks", case_main_blocks);
    failed |= run("sigwait-dedicated", case_sigwait_dedicated);
    failed |= run("sigpending-union", case_sigpending_union);
    failed |= run("signalfd-other-thread", case_signalfd_other_thread);
    failed |= run("unblock-takes-shared", case_unblock_takes_shared);
    failed |= run("sigsuspend-worker", case_sigsuspend_worker);
    failed |= run("rt-queue-order", case_rt_queue_order);
    failed |= run("fatal-group", case_fatal_group);
    failed |= run("group-stop", case_group_stop);
    if (failed)
        return 1;
    w("procsig-thread-ok\n");
    return 0;
}
