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
#include <errno.h>

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
    if (!(info.si_pid == pid && info.si_status == 7 &&
          info.si_code == CLD_EXITED)) {
        w("waitid-fail: fields\n");
        return 1;
    }

    /* Blocking waitid for a child that has ALREADY been reaped must return
     * ECHILD, not block. Linux decides this in kernel/exit.c::do_wait: the
     * tasklist walk finds no eligible child and returns -ECHILD.
     *
     * This is not a cosmetic errno. NARF parks a blocking waitid in
     * own_stack_wait_child, which registers only the child-exit and signal
     * wakers — it arms no timer-wheel backstop, so unlike a poll/epoll park
     * there is nothing to re-float the task. Without the guard this call
     * never returns, and the strand is invisible to the park-check
     * heuristic because that path does not tick dbg_park_checks either.
     * sys_wait4 has had the equivalent guard since a parent that reaped its
     * last child hung forever; waitid did not.
     *
     * alarm() bounds the hang so the failure is a token, not a dead run. */
    alarm(10);
    memset(&info, 0, sizeof info);
    errno = 0;
    if (waitid(P_PID, pid, &info, WEXITED) != -1 || errno != ECHILD) {
        w("waitid-fail: reaped child did not report ECHILD\n");
        return 1;
    }

    /* Same for a pid that was never our child at all. */
    memset(&info, 0, sizeof info);
    errno = 0;
    if (waitid(P_PID, 999999, &info, WEXITED) != -1 || errno != ECHILD) {
        w("waitid-fail: stranger pid did not report ECHILD\n");
        return 1;
    }
    alarm(0);

    w("waitid-ok\n");
    return 0;
}
