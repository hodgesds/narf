/* Threading demo for the NARF linux-compat smoketest.
 *
 * Spawns one pthread, both print, joins. End-to-end exercises clone +
 * per-thread TLS + futex (for pthread_join) + writev (stdio from
 * both threads).
 *
 * Build via REGEN_pthread.sh in this directory (requires musl-gcc).
 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static void *worker(void *arg) {
    (void)arg;
    /* Use raw write(2) to bypass stdio; we want to know whether the
     * worker thread *ran*, separately from whether it can flush
     * stdio. */
    static const char msg[] = "hello from worker\n";
    write(1, msg, sizeof(msg) - 1);
    return NULL;
}

int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) {
        write(1, "create-fail\n", 12);
        return 1;
    }
    write(1, "hello from main\n", 16);
    pthread_join(t, NULL);
    write(1, "joined\n", 7);
    return 0;
}
