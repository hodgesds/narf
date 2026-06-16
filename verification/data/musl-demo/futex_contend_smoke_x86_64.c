// Contended-multithreading smoke. Drives real cross-thread futex
// FUTEX_WAIT/FUTEX_WAKE traffic through three blocking paths that the
// single-threaded futex2_smoke can't reach:
//
//   1. A shared counter bumped under a pthread_mutex by N worker
//      threads — lock collisions take the kernel futex path.
//   2. pthread_join on each worker — the canonical block-until-wake:
//      the joiner FUTEX_WAITs on the child-tid word, woken by the
//      thread's exit FUTEX_WAKE (CLONE_CHILD_CLEARTID).
//   3. A condition-variable ping-pong — cond_wait/signal, i.e.
//      FUTEX_WAIT + the wake/requeue path, under a predicate loop (so
//      a lost or spurious wake surfaces as a hang, not a pass).
//
// This is also the regression test for the mmap thread-stack bug: a
// process spawning a 2nd thread used to get that thread's stack mapped
// across the canonical boundary and #GP-killed silently. A correct
// kernel finishes with counter == N*ITERS and rounds == ROUNDS.
// Success token "futex-contend-ok".
//
// Build: see REGEN_futex_contend_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define NTHREAD 4
#define ITERS 4000
#define ROUNDS 200

// ── phase 1: contended counter + join ──
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static long counter = 0;

static void *bump(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

// ── phase 2: condvar ping-pong ──
static pthread_mutex_t cmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int turn = 0; // 0 = main's turn, 1 = pong's turn
static int rounds_done = 0;

static void *pong(void *arg) {
    (void)arg;
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&cmtx);
        while (turn != 1)
            pthread_cond_wait(&cv, &cmtx);
        turn = 0;
        rounds_done++;
        pthread_cond_signal(&cv);
        pthread_mutex_unlock(&cmtx);
    }
    return NULL;
}

int main(void) {
    pthread_t t[NTHREAD];
    for (int i = 0; i < NTHREAD; i++) {
        if (pthread_create(&t[i], NULL, bump, NULL) != 0) {
            w("futex-fail: create\n");
            return 1;
        }
    }
    for (int i = 0; i < NTHREAD; i++)
        pthread_join(t[i], NULL);
    if (counter != (long)NTHREAD * ITERS) {
        w("futex-fail: count\n");
        return 1;
    }

    pthread_t p;
    if (pthread_create(&p, NULL, pong, NULL) != 0) {
        w("futex-fail: create2\n");
        return 1;
    }
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&cmtx);
        turn = 1;
        pthread_cond_signal(&cv);
        while (turn != 0)
            pthread_cond_wait(&cv, &cmtx);
        pthread_mutex_unlock(&cmtx);
    }
    pthread_join(p, NULL);
    if (rounds_done != ROUNDS) {
        w("futex-fail: rounds\n");
        return 1;
    }

    w("futex-contend-ok\n");
    return 0;
}
