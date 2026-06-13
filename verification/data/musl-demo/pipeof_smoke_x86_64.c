// Pipe blocking-read + EOF-on-writer-exit smoke. This is the kernel
// mechanism a shell's `$(...)` command substitution relies on.
//
// A child writes "hello" to a pipe then _exit()s WITHOUT closing its
// write end. The parent (after closing its own write end) reads the
// pipe until EOF. For this to work the kernel must:
//   1. Block the parent's read until the child's data arrives, rather
//      than returning a premature 0 the reader treats as EOF.
//   2. Release the child's pipe write fd when it exits (fd table
//      teardown on exit) so the parent's next read sees a real EOF (0)
//      instead of blocking forever.
// Success token "pipeof-ok".
//
// Build: see REGEN_pipeof_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int p[2];
    if (pipe(p) != 0) {
        w("pipeof-fail: pipe\n");
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        w("pipeof-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        close(p[0]);
        write(p[1], "hello", 5);
        // Deliberately do NOT close(p[1]) — rely on exit to release it.
        _exit(0);
    }
    // Parent: close our write end so the child's is the only one left.
    close(p[1]);
    char buf[64];
    int total = 0;
    for (;;) {
        int n = read(p[0], buf + total, (int)sizeof buf - total);
        if (n > 0) {
            total += n;
        } else if (n == 0) {
            break; // EOF — child's write end closed on exit
        } else {
            w("pipeof-fail: read\n");
            return 1;
        }
    }
    waitpid(pid, NULL, 0);
    if (total == 5 && memcmp(buf, "hello", 5) == 0) {
        w("pipeof-ok\n");
    } else {
        w("pipeof-fail: data\n");
    }
    return 0;
}
