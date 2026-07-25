// Live PTRACE_SYSCALL smoke — a real userspace strace loop. Exercises the
// end-to-end ptrace path the kernel-test unit test can't (it drives the state
// machine directly, with no live user frame): TRACEME, the tracee's initial
// SIGSTOP reported to a PLAIN waitpid (no WUNTRACED — ptrace-stops are reported
// unconditionally), PTRACE_SETOPTIONS(TRACESYSGOOD), PTRACE_SYSCALL stepping
// with SIGTRAP|0x80 syscall-stops, and PTRACE_GETREGS reporting orig_rax.
//
// The child raises SIGSTOP (sync), then makes two getpid() calls; the tracer
// single-steps by syscall and must observe the getpid syscall number (x86_64
// nr 39) at both an entry-stop and an exit-stop. Success token "strace-ok".
//
// Build: see REGEN_strace_smoke.sh (musl-gcc, PIE).
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

static void w(const char *m) { write(1, m, strlen(m)); }

static pid_t waitpid_nointr(pid_t pid, int *status) {
    pid_t r;
    do {
        r = waitpid(pid, status, 0);
    } while (r < 0 && errno == EINTR);
    return r;
}

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif
#define SYS_getpid_x86_64 39

int main(void) {
    pid_t c = fork();
    if (c == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            w("strace-fail: PTRACE_TRACEME request failed\n");
            _exit(1);
        }
        raise(SIGSTOP);
        getpid();
        getpid();
        _exit(0);
    }

    int st;
    // Plain waitpid (options = 0): a ptrace-stop must be reported anyway.
    if (waitpid_nointr(c, &st) != c || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        w("strace-fail: initial SIGSTOP stop not reported to plain waitpid\n");
        return 1;
    }
    ptrace(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACESYSGOOD);

    int getpid_stops = 0;
    int sysgood_stops = 0;
    for (int i = 0; i < 64; i++) {
        if (ptrace(PTRACE_SYSCALL, c, 0, 0) != 0) {
            w("strace-fail: PTRACE_SYSCALL request failed\n");
            return 1;
        }
        if (waitpid_nointr(c, &st) != c) {
            w("strace-fail: waitpid\n");
            return 1;
        }
        if (WIFEXITED(st)) {
            break;
        }
        if (!WIFSTOPPED(st)) {
            w("strace-fail: unexpected wait status\n");
            return 1;
        }
        if (WSTOPSIG(st) == (SIGTRAP | 0x80)) {
            sysgood_stops++;
        }
        struct user_regs_struct r;
        memset(&r, 0, sizeof(r));
        if (ptrace(PTRACE_GETREGS, c, 0, &r) != 0) {
            w("strace-fail: GETREGS\n");
            return 1;
        }
        if (r.orig_rax == SYS_getpid_x86_64) {
            getpid_stops++;
        }
    }

    // Two getpid() calls, each an entry-stop + an exit-stop = at least 2 seen
    // (and the SIGTRAP|0x80 TRACESYSGOOD marker must have appeared).
    if (getpid_stops < 2) {
        w("strace-fail: getpid syscall not observed via orig_rax\n");
        return 1;
    }
    if (sysgood_stops == 0) {
        w("strace-fail: no SIGTRAP|0x80 (TRACESYSGOOD) syscall-stop\n");
        return 1;
    }
    w("strace-ok\n");
    return 0;
}
