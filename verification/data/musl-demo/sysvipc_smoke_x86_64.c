// System V semaphores + message queues smoke. Exercises the create →
// op → control → remove flow for both. semctl is issued raw (it is a
// varargs/union-semun call) while the data ops use the musl wrappers.
// Success token "sysvipc-ok".
//
// Build: see REGEN_sysvipc_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/syscall.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // ── semaphores ──
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid < 0) { w("sysvipc-fail: semget\n"); return 1; }
    if (syscall(SYS_semctl, semid, 0, SETVAL, 3) != 0) { w("sysvipc-fail: setval\n"); return 1; }

    struct sembuf p = { 0, -1, 0 }; // acquire
    if (semop(semid, &p, 1) != 0) { w("sysvipc-fail: semop-p\n"); return 1; }
    if (syscall(SYS_semctl, semid, 0, GETVAL) != 2) { w("sysvipc-fail: getval-2\n"); return 1; }

    struct sembuf v = { 0, 1, 0 }; // release
    if (semop(semid, &v, 1) != 0) { w("sysvipc-fail: semop-v\n"); return 1; }
    if (syscall(SYS_semctl, semid, 0, GETVAL) != 3) { w("sysvipc-fail: getval-3\n"); return 1; }
    if (syscall(SYS_semctl, semid, 0, IPC_RMID) != 0) { w("sysvipc-fail: sem-rmid\n"); return 1; }

    // ── message queue ──
    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msqid < 0) { w("sysvipc-fail: msgget\n"); return 1; }

    struct { long mtype; char mtext[32]; } snd, rcv;
    snd.mtype = 5;
    memcpy(snd.mtext, "sysv-msg", 8);
    if (msgsnd(msqid, &snd, 8, 0) != 0) { w("sysvipc-fail: msgsnd\n"); return 1; }

    memset(&rcv, 0, sizeof rcv);
    ssize_t n = msgrcv(msqid, &rcv, sizeof rcv.mtext, 0, 0);
    if (n != 8 || rcv.mtype != 5 || memcmp(rcv.mtext, "sysv-msg", 8) != 0) {
        w("sysvipc-fail: msgrcv\n"); return 1;
    }
    if (msgctl(msqid, IPC_RMID, 0) != 0) { w("sysvipc-fail: msg-rmid\n"); return 1; }

    w("sysvipc-ok\n");
    return 0;
}
