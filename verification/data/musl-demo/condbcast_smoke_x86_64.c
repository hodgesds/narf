// pthread_cond_broadcast handoff smoke — the FUTEX_REQUEUE path.
//
// musl's condvar puts each private-cond waiter to sleep on its own
// stack-local `barrier` futex word. `pthread_cond_broadcast` wakes only
// the OLDEST signaled waiter directly; every other signaled waiter is
// handed off in a chain — the waiter that just woke re-locks the mutex
// and calls `unlock_requeue(&node.prev->barrier, &m->_m_lock, ...)`,
// which zeroes the next waiter's barrier word WITHOUT waking it and
// issues FUTEX_REQUEUE to move that (still-parked) waiter's kernel wait
// from the barrier word onto the mutex word, so the eventual mutex
// unlock wakes it (src/thread/pthread_cond_timedwait.c).
//
// A kernel that silently drops FUTEX_REQUEUE (returns an error other
// than -ENOSYS, so musl's `__syscall(...) != -ENOSYS ||` fallback chain
// treats it as done) strands that waiter FOREVER: its barrier word is
// already 0, so no further signal/broadcast ever wakes the word again
// (musl's `unlock()` only issues FUTEX_WAKE when the swap saw 2), and
// the waiter sleeps in a futex wait no one will ever wake. That is a
// permanent, deterministic hang of any app that broadcasts to >= 2
// parked waiters — the compositor/desktop class of workload.
//
// This smoke parks NTHREAD waiters on one condvar, broadcasts, and
// requires every waiter to re-acquire the mutex and ack, ROUNDS times.
// A correct kernel finishes with acks == NTHREAD * ROUNDS. Success
// token "condbcast-ok".
//
// Build: see REGEN_condbcast_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define NTHREAD 4
#define ROUNDS 50

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t cv_ack = PTHREAD_COND_INITIALIZER;
static int go = 0;    // round counter: waiters proceed when go > r
static int acks = 0;  // total acks across all rounds

static void *waiter(void *arg) {
    (void)arg;
    for (int r = 0; r < ROUNDS; r++) {
        pthread_mutex_lock(&mtx);
        while (go <= r)
            pthread_cond_wait(&cv, &mtx);
        acks++;
        pthread_cond_signal(&cv_ack);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

int main(void) {
    pthread_t t[NTHREAD];
    for (int i = 0; i < NTHREAD; i++) {
        if (pthread_create(&t[i], NULL, waiter, NULL) != 0) {
            w("condbcast-fail: create\n");
            return 1;
        }
    }
    for (int r = 0; r < ROUNDS; r++) {
        // Let all waiters actually PARK on the condvar before the
        // broadcast, so the requeue handoff chain (not the trivial
        // nobody-waiting case) is what gets exercised.
        usleep(20000);
        pthread_mutex_lock(&mtx);
        go = r + 1;
        pthread_cond_broadcast(&cv);
        while (acks < (r + 1) * NTHREAD)
            pthread_cond_wait(&cv_ack, &mtx);
        pthread_mutex_unlock(&mtx);
    }
    for (int i = 0; i < NTHREAD; i++)
        pthread_join(t[i], NULL);
    if (acks != NTHREAD * ROUNDS) {
        w("condbcast-fail: acks\n");
        return 1;
    }
    w("condbcast-ok\n");
    return 0;
}
