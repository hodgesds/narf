// waitid(2) smoke. Fork a child that exits with code 7, reap it with
// waitid(P_PID, WEXITED), and verify the returned siginfo_t describes a
// normal exit (si_code == CLD_EXITED, si_pid == child, si_status == 7).
// Exercises the blocking wait path's siginfo writeback. Success token
// "waitid-ok".
//
// Build: see REGEN_waitid_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        w("waitid-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        _exit(7);
    }

    siginfo_t info;
    memset(&info, 0, sizeof info);
    if (waitid(P_PID, pid, &info, WEXITED) != 0) {
        w("waitid-fail: waitid\n");
        return 1;
    }
    if (info.si_pid == pid && info.si_status == 7 &&
        info.si_code == CLD_EXITED) {
        w("waitid-ok\n");
    } else {
        w("waitid-fail: fields\n");
    }
    return 0;
}
