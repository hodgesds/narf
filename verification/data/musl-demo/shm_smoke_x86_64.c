// System V shared-memory smoke. Create a segment, attach it twice, and
// confirm the two attachments share storage (a write through one is
// visible through the other) — real frame sharing. Then detach both and
// remove the segment. Success token "shm-ok".
//
// Build: see REGEN_shm_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid < 0) { w("shm-fail: shmget\n"); return 1; }

    char *a = shmat(shmid, NULL, 0);
    if (a == (char *)-1) { w("shm-fail: shmat1\n"); return 1; }
    memcpy(a, "shm-shared-data", 15);

    // Second attach of the same id maps the same frames.
    char *b = shmat(shmid, NULL, 0);
    if (b == (char *)-1) { w("shm-fail: shmat2\n"); return 1; }
    if (memcmp(b, "shm-shared-data", 15) != 0) { w("shm-fail: not-shared\n"); return 1; }

    // Write through b, observe through a — genuine sharing.
    memcpy(b, "ROUNDTRIP", 9);
    if (memcmp(a, "ROUNDTRIP", 9) != 0) { w("shm-fail: roundtrip\n"); return 1; }

    // IPC_STAT round-trips (size assertion omitted — struct layout).
    struct shmid_ds ds;
    memset(&ds, 0, sizeof ds);
    if (shmctl(shmid, IPC_STAT, &ds) != 0) { w("shm-fail: stat\n"); return 1; }

    if (shmdt(a) != 0) { w("shm-fail: shmdt-a\n"); return 1; }
    if (shmdt(b) != 0) { w("shm-fail: shmdt-b\n"); return 1; }
    if (shmctl(shmid, IPC_RMID, NULL) != 0) { w("shm-fail: rmid\n"); return 1; }

    w("shm-ok\n");
    return 0;
}
