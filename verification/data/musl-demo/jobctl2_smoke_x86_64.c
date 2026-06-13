// Job-control stop/continue smoke. Fork a child that stops itself with
// SIGSTOP; the parent observes the stop via waitpid(WUNTRACED), resumes
// the child with SIGCONT, observes the continue via waitpid(WCONTINUED),
// then reaps the normal exit. This is the machinery an interactive shell
// relies on for ^Z / fg / bg (real process stop + resume, not a stub).
// Success token "jobctl2-ok".
//
// The child stops itself with a translation-free raw tkill(gettid(),
// SIGSTOP) rather than libc raise() so the pending bit lands on exactly
// the TaskId the kernel's signal-delivery path keys on.
//
// Build: see REGEN_jobctl2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#ifndef SYS_tkill
#define SYS_tkill 200
#endif
#ifndef SYS_gettid
#define SYS_gettid 186
#endif

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        w("jobctl2-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        // Stop ourselves. The parent observes the stop, then resumes us
        // with SIGCONT — execution continues right here and we exit 42.
        long tid = syscall(SYS_gettid);
        syscall(SYS_tkill, tid, SIGSTOP);
        _exit(42);
    }

    int st;

    // 1. The child must actually stop: WIFSTOPPED with WSTOPSIG==SIGSTOP.
    pid_t r = waitpid(pid, &st, WUNTRACED);
    if (r != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        w("jobctl2-fail: stop\n");
        return 1;
    }

    // 2. Resume it.
    if (kill(pid, SIGCONT) != 0) {
        w("jobctl2-fail: cont\n");
        return 1;
    }

    // 3. The resume is reported: WIFCONTINUED.
    r = waitpid(pid, &st, WCONTINUED);
    if (r != pid || !WIFCONTINUED(st)) {
        w("jobctl2-fail: continued\n");
        return 1;
    }

    // 4. The continued child runs to completion: WIFEXITED, code 42.
    r = waitpid(pid, &st, 0);
    if (r != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 42) {
        w("jobctl2-fail: exit\n");
        return 1;
    }

    w("jobctl2-ok\n");
    return 0;
}
