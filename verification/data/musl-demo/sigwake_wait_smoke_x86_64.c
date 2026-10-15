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
//
// Timed sleeps (the "timed/..." cases): a signal that is DELIVERABLE to the
// sleeping thread interrupts a finite-timeout poll, ppoll, select, pselect6,
// epoll_wait, nanosleep, clock_nanosleep and FUTEX_WAIT at once and returns
// EINTR with or without SA_RESTART (Linux: ERESTARTNOHAND /
// ERESTART_RESTARTBLOCK / EINTR all surface as EINTR once a handler runs),
// writing back the remaining time where Linux does (nanosleep's rem, select's
// timeval, ppoll's and pselect6's timespec). A BLOCKED or IGNORED signal never
// wakes the sleeper (Linux complete_signal only wakes a thread that
// wants_signal; prepare_signal drops ignored signals), so it must not shorten
// the sleep at all.
//
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
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
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

// ── Timed interruptible sleeps ──────────────────────────────────────

enum tsleep {
    T_POLL,
    T_PPOLL,
    T_SELECT,
    T_PSELECT,
    T_EPOLL,
    T_NANOSLEEP,
    T_CLOCK_NANOSLEEP,
    T_FUTEX,
    T_FUTEX_BITSET_ABS,
    T_COUNT
};
static const char *tsleep_name[] = {"poll",       "ppoll",     "select",
                                    "pselect6",   "epoll_wait", "nanosleep",
                                    "clock_nanosleep", "futex_wait", "futex_bitset_abs"};

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static volatile int timed_handled;
static void on_timed(int sig) {
    (void)sig;
    timed_handled++;
}

struct sender {
    pid_t tid;
    int sig;
    int delay_ms;
    int group; // kill(getpid()) instead of tgkill(tid)
};
static void *send_worker(void *arg) {
    struct sender *s = arg;
    usleep(s->delay_ms * 1000);
    if (s->group)
        kill(getpid(), s->sig);
    else
        syscall(SYS_tgkill, getpid(), s->tid, s->sig);
    return NULL;
}

// The sender runs with every signal blocked, so a process-directed signal can
// only be taken by the sleeping thread.
static pthread_t start_sender(struct sender *s) {
    sigset_t old;
    pthread_t t;
    block_all_in_this_thread(&old);
    pthread_create(&t, NULL, send_worker, s);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    return t;
}

static volatile int tfutex;
static int tpipe[2];

// Sleep `ms` in primitive `k` through the raw syscall, so the kernel's own
// time write-back is visible. Returns the syscall result with *err = errno and
// *rem_ms = the remaining time the kernel wrote back (-1 where none).
static long timed_sleep(enum tsleep k, int ms, int *err, long *rem_ms) {
    long r = -1;
    *rem_ms = -1;
    errno = 0;
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000};
    switch (k) {
    case T_POLL: {
        struct pollfd p = {tpipe[0], POLLIN, 0};
        r = syscall(SYS_poll, &p, 1, ms);
        break;
    }
    case T_PPOLL: {
        struct pollfd p = {tpipe[0], POLLIN, 0};
        r = syscall(SYS_ppoll, &p, 1, &ts, NULL, 8);
        *rem_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        break;
    }
    case T_SELECT: {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(tpipe[0], &rf);
        struct timeval tv = {ms / 1000, (long)(ms % 1000) * 1000};
        r = syscall(SYS_select, tpipe[0] + 1, &rf, NULL, NULL, &tv);
        *rem_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
        break;
    }
    case T_PSELECT: {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(tpipe[0], &rf);
        r = syscall(SYS_pselect6, tpipe[0] + 1, &rf, NULL, NULL, &ts, NULL);
        *rem_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        break;
    }
    case T_EPOLL: {
        int ep = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = tpipe[0]}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, tpipe[0], &ev);
        errno = 0;
        r = syscall(SYS_epoll_wait, ep, &out, 1, ms);
        *err = errno;
        close(ep);
        return r;
    }
    case T_NANOSLEEP: {
        struct timespec rem = {-1, -1};
        r = syscall(SYS_nanosleep, &ts, &rem);
        if (r != 0)
            *rem_ms = rem.tv_sec * 1000 + rem.tv_nsec / 1000000;
        break;
    }
    case T_CLOCK_NANOSLEEP: {
        struct timespec rem = {-1, -1};
        r = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &ts, &rem);
        if (r != 0)
            *rem_ms = rem.tv_sec * 1000 + rem.tv_nsec / 1000000;
        break;
    }
    case T_FUTEX:
        tfutex = 0;
        r = syscall(SYS_futex, &tfutex, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
        break;
    case T_FUTEX_BITSET_ABS: {
        struct timespec abs;
        clock_gettime(CLOCK_MONOTONIC, &abs);
        abs.tv_sec += ts.tv_sec;
        abs.tv_nsec += ts.tv_nsec;
        if (abs.tv_nsec >= 1000000000) {
            abs.tv_sec++;
            abs.tv_nsec -= 1000000000;
        }
        tfutex = 0;
        r = syscall(SYS_futex, &tfutex, FUTEX_WAIT_BITSET_PRIVATE, 0, &abs, NULL,
                    FUTEX_BITSET_MATCH_ANY);
        break;
    }
    default:
        break;
    }
    *err = errno;
    return r;
}

static int tfail(enum tsleep k, const char *what, const char *detail) {
    char buf[224];
    int n = snprintf(buf, sizeof buf, "sigwake-wait-fail: case=timed/%s/%s %s\n", tsleep_name[k],
                     what, detail);
    write(1, buf, n);
    return 1;
}

// A deliverable signal (handler installed, unblocked) sent from another thread
// 200 ms in must end a 5 s sleep within ~100 ms of the send, with EINTR,
// SA_RESTART or not, and the time written back must be what is left.
static int timed_interrupt(enum tsleep k, int restart, int group) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_timed;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigaction(SIGUSR1, &sa, NULL);
    timed_handled = 0;
    struct sender s = {gettid_(), SIGUSR1, 200, group};
    long long t0 = now_ms();
    pthread_t t = start_sender(&s);
    int err;
    long rem;
    long r = timed_sleep(k, 5000, &err, &rem);
    long long el = now_ms() - t0;
    pthread_join(t, NULL);
    char d[160];
    const char *what =
        group ? (restart ? "kill-sa_restart" : "kill") : (restart ? "tgkill-sa_restart" : "tgkill");
    if (r != -1 || err != EINTR) {
        snprintf(d, sizeof d, "returned %ld errno %d after %lld ms (want -1 EINTR)", r, err, el);
        return tfail(k, what, d);
    }
    if (el > 300) {
        snprintf(d, sizeof d, "interrupted only after %lld ms (signal sent at 200 ms)", el);
        return tfail(k, what, d);
    }
    if (timed_handled != 1) {
        snprintf(d, sizeof d, "handler ran %d times", timed_handled);
        return tfail(k, what, d);
    }
    // The primitives that write back the remaining time: ~5000 - elapsed.
    if (k == T_NANOSLEEP || k == T_CLOCK_NANOSLEEP || k == T_SELECT || k == T_PPOLL ||
        k == T_PSELECT) {
        long want = 5000 - el;
        if (rem < want - 100 || rem > want + 100) {
            snprintf(d, sizeof d, "remaining %ld ms, want ~%ld (elapsed %lld)", rem, want, el);
            return tfail(k, what, d);
        }
    }
    return 0;
}

// A signal the sleeper BLOCKS (thread-directed tgkill, or process-directed
// with every thread blocking it), or one that is IGNORED (SIG_IGN, or SIGCHLD
// at SIG_DFL), must not shorten a 300 ms sleep: it times out normally.
enum quiet { Q_BLOCKED_TGKILL, Q_BLOCKED_KILL, Q_SIG_IGN, Q_DFL_IGNORE, Q_COUNT };
static const char *quiet_name[] = {"blocked-tgkill", "blocked-kill", "sig_ign", "sigchld-dfl"};

static int timed_quiet_body(enum tsleep k, enum quiet q) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    int sig = SIGUSR2;
    if (q == Q_SIG_IGN) {
        sa.sa_handler = SIG_IGN;
    } else if (q == Q_DFL_IGNORE) {
        sig = SIGCHLD;
        sa.sa_handler = SIG_DFL;
    } else {
        sa.sa_handler = on_timed;
    }
    sigaction(sig, &sa, NULL);
    sigset_t blk, old;
    sigemptyset(&blk);
    sigaddset(&blk, sig);
    int blocked = q == Q_BLOCKED_TGKILL || q == Q_BLOCKED_KILL;
    if (blocked)
        pthread_sigmask(SIG_BLOCK, &blk, &old);
    timed_handled = 0;
    struct sender s = {gettid_(), sig, 50, q == Q_BLOCKED_KILL};
    long long t0 = now_ms();
    pthread_t t = start_sender(&s);
    int err;
    long rem;
    long r = timed_sleep(k, 300, &err, &rem);
    long long el = now_ms() - t0;
    pthread_join(t, NULL);
    // The timeout result: 0, except FUTEX_WAIT's -1 ETIMEDOUT.
    int futex = k == T_FUTEX || k == T_FUTEX_BITSET_ABS;
    char d[160];
    if (futex ? (r != -1 || err != ETIMEDOUT) : r != 0) {
        snprintf(d, sizeof d, "returned %ld errno %d after %lld ms (want the timeout result)", r,
                 err, el);
        return tfail(k, quiet_name[q], d);
    }
    if (el < 295) {
        snprintf(d, sizeof d, "300 ms sleep cut short to %lld ms", el);
        return tfail(k, quiet_name[q], d);
    }
    // Nor stretched: a fresh call must not inherit an earlier, interrupted
    // call's deadline.
    if (el > 1000) {
        snprintf(d, sizeof d, "300 ms sleep took %lld ms", el);
        return tfail(k, quiet_name[q], d);
    }
    if (timed_handled != 0) {
        snprintf(d, sizeof d, "handler ran %d times during the sleep", timed_handled);
        return tfail(k, quiet_name[q], d);
    }
    if (blocked) {
        // Left pending; unblocking delivers it at once.
        sigset_t pend;
        sigpending(&pend);
        if (!sigismember(&pend, sig))
            return tfail(k, quiet_name[q], "blocked signal not left pending");
        pthread_sigmask(SIG_SETMASK, &old, NULL);
        if (timed_handled != 1) {
            sigpending(&pend);
            snprintf(d, sizeof d,
                     "unblocking ran the handler %d times (want 1), still pending=%d",
                     timed_handled, sigismember(&pend, sig));
            return tfail(k, quiet_name[q], d);
        }
    }
    return 0;
}

// A failed check returns before the unblock: put the mask back so one failure
// does not leave the signal blocked for every case after it.
static int timed_quiet(enum tsleep k, enum quiet q) {
    sigset_t entry;
    pthread_sigmask(SIG_SETMASK, NULL, &entry);
    int rc = timed_quiet_body(k, q);
    pthread_sigmask(SIG_SETMASK, &entry, NULL);
    return rc;
}

// A stop and continue runs no handler, so the interrupted sleep restarts
// (-ERESTARTNOHAND / -ERESTART_RESTARTBLOCK) to its ORIGINAL expiry: a 300 ms
// sleep stopped for ~50 ms still times out at ~300 ms, never 300 ms after the
// continue. epoll_wait is the exception (signal(7), "Interruption of system
// calls ... by stop signals"): ep_poll returns a plain -EINTR, which is not
// restarted.
static int timed_stopcont(enum tsleep k) {
    pid_t parent = getpid();
    long long t0 = now_ms();
    pid_t child = fork();
    if (child == 0) {
        usleep(50000);
        kill(parent, SIGSTOP);
        usleep(50000);
        kill(parent, SIGCONT);
        _exit(0);
    }
    int err;
    long rem;
    long r = timed_sleep(k, 300, &err, &rem);
    long long el = now_ms() - t0;
    waitpid(child, NULL, 0);
    char d[160];
    if (k == T_EPOLL) {
        if (r != -1 || err != EINTR) {
            snprintf(d, sizeof d, "returned %ld errno %d after %lld ms (want -1 EINTR)", r, err,
                     el);
            return tfail(k, "stop-cont", d);
        }
        return 0;
    }
    int futex = k == T_FUTEX || k == T_FUTEX_BITSET_ABS;
    if (futex ? (r != -1 || err != ETIMEDOUT) : r != 0) {
        snprintf(d, sizeof d, "returned %ld errno %d after %lld ms (want the timeout result)", r,
                 err, el);
        return tfail(k, "stop-cont", d);
    }
    if (el < 295 || el > 1000) {
        snprintf(d, sizeof d, "300 ms sleep across a stop took %lld ms", el);
        return tfail(k, "stop-cont", d);
    }
    return 0;
}

// ppoll / pselect6 / epoll_pwait wait under the mask they are given. A
// signal the thread blocks but that mask unblocks — already pending at the
// call, or sent 200 ms into a 5 s wait — runs its handler and ends the call
// with EINTR; afterwards the thread's own mask is back (the handler's
// sigreturn restores it), so the signal is blocked again.
enum mwait { M_PPOLL, M_PSELECT, M_EPOLL_PWAIT, M_COUNT };
static const char *mwait_name[] = {"ppoll", "pselect6", "epoll_pwait"};

static int mfail(enum mwait m, const char *what, const char *detail) {
    char buf[224];
    int n = snprintf(buf, sizeof buf, "sigwake-wait-fail: case=timed/%s/%s %s\n", mwait_name[m],
                     what, detail);
    write(1, buf, n);
    return 1;
}

static int timed_maskwait(enum mwait m, int pending_at_entry) {
    const char *what = pending_at_entry ? "mask-unblocks-pending" : "mask-unblocks-sent";
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_timed;
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t blk, old, during;
    sigemptyset(&blk);
    sigaddset(&blk, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &blk, &old);
    pthread_sigmask(SIG_SETMASK, NULL, &during);
    sigdelset(&during, SIGUSR1);
    timed_handled = 0;
    pthread_t t;
    struct sender s = {gettid_(), SIGUSR1, 200, 0};
    if (pending_at_entry)
        syscall(SYS_tgkill, getpid(), gettid_(), SIGUSR1);
    else
        t = start_sender(&s);
    long long t0 = now_ms();
    struct timespec ts = {5, 0};
    long r = -1;
    errno = 0;
    if (m == M_PPOLL) {
        struct pollfd p = {tpipe[0], POLLIN, 0};
        r = syscall(SYS_ppoll, &p, 1, &ts, &during, 8);
    } else if (m == M_PSELECT) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(tpipe[0], &rf);
        struct {
            const sigset_t *set;
            size_t size;
        } pack = {&during, 8};
        r = syscall(SYS_pselect6, tpipe[0] + 1, &rf, NULL, NULL, &ts, &pack);
    } else {
        int ep = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event ev = {.events = EPOLLIN, .data.fd = tpipe[0]}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, tpipe[0], &ev);
        errno = 0;
        r = syscall(SYS_epoll_pwait, ep, &out, 1, 5000, &during, 8);
        int e = errno;
        close(ep);
        errno = e;
    }
    int err = errno;
    long long el = now_ms() - t0;
    if (!pending_at_entry)
        pthread_join(t, NULL);
    sigset_t now_mask;
    pthread_sigmask(SIG_SETMASK, NULL, &now_mask);
    int still_blocked = sigismember(&now_mask, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    char d[160];
    if (r != -1 || err != EINTR) {
        snprintf(d, sizeof d, "returned %ld errno %d after %lld ms (want -1 EINTR)", r, err, el);
        return mfail(m, what, d);
    }
    if (el > (pending_at_entry ? 100 : 300)) {
        snprintf(d, sizeof d, "interrupted only after %lld ms", el);
        return mfail(m, what, d);
    }
    if (timed_handled != 1) {
        snprintf(d, sizeof d, "handler ran %d times", timed_handled);
        return mfail(m, what, d);
    }
    if (!still_blocked)
        return mfail(m, what, "the call's mask outlived it (SIGUSR1 left unblocked)");
    return 0;
}

static int run_timed(void) {
    if (pipe2(tpipe, O_CLOEXEC) != 0)
        return 1;
    // A signal-blocking idle worker, so a process-directed signal has a second
    // thread it must not pick.
    sigset_t old;
    block_all_in_this_thread(&old);
    pthread_t idle;
    pthread_create(&idle, NULL, idle_worker, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    int failed = 0;
    for (int k = 0; k < T_COUNT; k++) {
        cur_case = tsleep_name[k];
        for (int restart = 0; restart < 2; restart++)
            for (int group = 0; group < 2; group++)
                failed |= timed_interrupt(k, restart, group);
        for (int q = 0; q < Q_COUNT; q++)
            failed |= timed_quiet(k, q);
        failed |= timed_stopcont(k);
    }
    for (int m = 0; m < M_COUNT; m++) {
        cur_case = mwait_name[m];
        for (int early = 0; early < 2; early++)
            failed |= timed_maskwait(m, early);
    }
    pthread_mutex_lock(&mtx);
    workers_stop = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mtx);
    pthread_join(idle, NULL);
    return failed;
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
    {
        pid_t pid = fork();
        if (pid == 0) {
            cur_case = "timed";
            signal(SIGALRM, on_alarm);
            alarm(60);
            _exit(run_timed() ? 1 : 0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
            if (!WIFEXITED(status)) {
                char buf[96];
                int k = snprintf(buf, sizeof buf,
                                 "sigwake-wait-fail: case=timed died (status %#x)\n", status);
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
