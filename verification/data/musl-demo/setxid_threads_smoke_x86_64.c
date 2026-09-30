// set*id() in a multithreaded process whose threads are parked.
//
// glibc applies setuid/seteuid/setgid/... to every thread: __nptl_setxid
// tgkill()s SIGSETXID (33) to each other thread, whose handler repeats the
// syscall on itself and acknowledges through a futex the caller waits on
// (musl does the same with __synccall). So a thread that never runs the
// handler hangs the caller forever.
//
// That is the CachyOS Plasma wedge: Xwayland's keymap path calls seteuid()
// while Mesa's disk-cache workers sit in pthread_cond_wait. Mesa creates
// those threads with every signal blocked around pthread_create
// (u_thread_create); glibc additionally runs a new thread with a full
// internal mask until start_thread restores the intended one, and its
// pthread_sigmask never blocks 32/33. The worker never acknowledged, so
// Xwayland hung in __nptl_setxid, kwin (in a synchronous X11 round trip)
// stopped serving Wayland, and plasmashell was killed by its start timeout.
//
// Cases, each with threads parked in pthread_cond_wait during the call:
//   plain    threads created with the default mask
//   blocked  threads created with all signals blocked (Mesa's shape)
//   sigwait  threads parked in sigtimedwait instead of a condvar
// Build twice: musl (musl-demo) and static glibc (the `_glibc` variant).
//
// Success token "setxid-threads-ok".
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NTHREAD 3
#define ROUNDS 20

static void w(const char *m) { write(1, m, strlen(m)); }

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int stop = 0;
static int parked = 0;
static const char *phase = "start";

static void on_alarm(int sig) {
    (void)sig;
    char buf[96];
    int n = snprintf(buf, sizeof buf, "setxid-threads-fail: hung in case %s\n", phase);
    write(1, buf, n);
    _exit(1);
}

static void *cond_waiter(void *arg) {
    (void)arg;
    pthread_mutex_lock(&mtx);
    parked++;
    while (!stop)
        pthread_cond_wait(&cv, &mtx);
    pthread_mutex_unlock(&mtx);
    return NULL;
}

static void *sig_waiter(void *arg) {
    (void)arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    pthread_mutex_lock(&mtx);
    parked++;
    pthread_mutex_unlock(&mtx);
    struct timespec ts = {0, 50 * 1000 * 1000};
    for (;;) {
        pthread_mutex_lock(&mtx);
        int s = stop;
        pthread_mutex_unlock(&mtx);
        if (s)
            break;
        sigtimedwait(&set, NULL, &ts);
    }
    return NULL;
}

static int run_case(const char *name, void *(*fn)(void *), int block_all) {
    phase = name;
    pthread_t t[NTHREAD];
    stop = 0;
    parked = 0;
    sigset_t all, saved;
    sigfillset(&all);
    if (block_all)
        pthread_sigmask(SIG_BLOCK, &all, &saved);
    for (int i = 0; i < NTHREAD; i++) {
        if (pthread_create(&t[i], NULL, fn, NULL) != 0) {
            w("setxid-threads-fail: pthread_create\n");
            return -1;
        }
    }
    if (block_all)
        pthread_sigmask(SIG_SETMASK, &saved, NULL);
    // Wait until every thread is parked in its blocking call.
    for (;;) {
        pthread_mutex_lock(&mtx);
        int p = parked;
        pthread_mutex_unlock(&mtx);
        if (p == NTHREAD)
            break;
        usleep(1000);
    }
    usleep(20 * 1000);
    for (int r = 0; r < ROUNDS; r++) {
        if (seteuid(geteuid()) != 0 || setegid(getegid()) != 0) {
            w("setxid-threads-fail: seteuid/setegid\n");
            return -1;
        }
    }
    pthread_mutex_lock(&mtx);
    stop = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mtx);
    for (int i = 0; i < NTHREAD; i++)
        pthread_join(t[i], NULL);
    return 0;
}

int main(void) {
    signal(SIGALRM, on_alarm);
    alarm(30);
    if (run_case("plain", cond_waiter, 0) || run_case("blocked", cond_waiter, 1) ||
        run_case("sigwait", sig_waiter, 1))
        return 1;
    w("setxid-threads-ok\n");
    return 0;
}
