// Job-control stop/continue smoke. Fork a child, preserve an asynchronously
// interrupted RAX through SIGSTOP/SIGCONT, and verify that SA_NOCLDSTOP
// suppresses only SIGCHLD generation while waitpid still reports every
// stopped/continued state. This is the machinery an interactive shell and
// stress-ng --wait rely on (real process stop + resume, not a stub).
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
#include <errno.h>
#include <stdint.h>

#ifndef SYS_tkill
#define SYS_tkill 200
#endif
#ifndef SYS_gettid
#define SYS_gettid 186
#endif

static void w(const char *m) { write(1, m, strlen(m)); }

static volatile sig_atomic_t release_child;
static volatile sig_atomic_t sigchld_count;

static void release_handler(int sig) {
    (void)sig;
    release_child = 1;
}

static void sigchld_handler(int sig) {
    (void)sig;
    sigchld_count++;
}

static pid_t wait_nointr(pid_t pid, int *st, int options) {
    pid_t ret;
    do {
        ret = waitpid(pid, st, options);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static ssize_t read_nointr(int fd, void *buf, size_t len) {
    ssize_t ret;
    do {
        ret = read(fd, buf, len);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

int main(void) {
    int ready[2];
    if (pipe(ready) != 0) {
        w("jobctl2-fail: pipe\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = release_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        w("jobctl2-fail: sigusr1-action\n");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        w("jobctl2-fail: sigchld-action\n");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        w("jobctl2-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        close(ready[0]);
        // Tell the parent that the child is about to hold a live value in RAX
        // at an ordinary user instruction. The parent stops us there, resumes
        // us, then SIGUSR1 releases the loop. Signal stop/resume and sigreturn
        // must preserve RAX exactly; this catches a stop path that writes a
        // fabricated syscall return into an asynchronously interrupted frame.
        char token = 'R';
        if (write(ready[1], &token, 1) != 1)
            _exit(44);
        close(ready[1]);
        register uint64_t interrupted_rax asm("rax") =
            UINT64_C(0xa55a5aa5deadbeef);
        asm volatile(
            "1: cmpl $0, %1\n\t"
            "je 1b"
            : "+a"(interrupted_rax)
            : "m"(release_child)
            : "cc", "memory");
        if (interrupted_rax != UINT64_C(0xa55a5aa5deadbeef))
            _exit(45);
        release_child = 0;

        // Stop ourselves. The parent repeatedly resumes and stops us before
        // SIGUSR1 releases the pause loop.
        long tid = syscall(SYS_gettid);
        syscall(SYS_tkill, tid, SIGSTOP);
        while (!release_child)
            pause();
        _exit(42);
    }

    close(ready[1]);
    int st;
    pid_t r;
    char token = 0;
    if (read_nointr(ready[0], &token, 1) != 1 || token != 'R') {
        w("jobctl2-fail: ready\n");
        return 1;
    }
    close(ready[0]);
    if (kill(pid, SIGSTOP) != 0) {
        w("jobctl2-fail: async-stop\n");
        return 1;
    }
    r = wait_nointr(pid, &st, WUNTRACED);
    if (r != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        w("jobctl2-fail: async-stopped\n");
        return 1;
    }
    if (kill(pid, SIGCONT) != 0) {
        w("jobctl2-fail: async-cont\n");
        return 1;
    }
    r = wait_nointr(pid, &st, WCONTINUED);
    if (r != pid || !WIFCONTINUED(st)) {
        w("jobctl2-fail: async-continued\n");
        return 1;
    }
    if (kill(pid, SIGUSR1) != 0) {
        w("jobctl2-fail: async-release\n");
        return 1;
    }

    for (int i = 0; i < 128; i++) {
        r = wait_nointr(pid, &st, WUNTRACED);
        if (r != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
            w("jobctl2-fail: stop\n");
            return 1;
        }
        if (kill(pid, SIGCONT) != 0) {
            w("jobctl2-fail: cont\n");
            return 1;
        }
        r = wait_nointr(pid, &st, WCONTINUED);
        if (r != pid || !WIFCONTINUED(st)) {
            w("jobctl2-fail: continued\n");
            return 1;
        }
        if (i != 127 && kill(pid, SIGSTOP) != 0) {
            w("jobctl2-fail: restop\n");
            return 1;
        }
    }

    if (sigchld_count != 0) {
        w("jobctl2-fail: SA_NOCLDSTOP\n");
        return 1;
    }
    if (kill(pid, SIGUSR1) != 0) {
        w("jobctl2-fail: release\n");
        return 1;
    }

    // The released child exits normally with code 42.
    r = wait_nointr(pid, &st, 0);
    if (r != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 42) {
        w("jobctl2-fail: exit\n");
        return 1;
    }

    w("jobctl2-ok\n");
    return 0;
}
