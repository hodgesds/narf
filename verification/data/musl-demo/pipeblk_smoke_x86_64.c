// Regression smoke for blocking pipe writes. A pipe's buffer is finite
// (NARF: 64 KiB); POSIX says a blocking write to a FULL pipe must BLOCK until
// the reader drains room, never return a spurious 0. NARF previously had a
// blocking read but no blocking write — a full-pipe write returned 0, so
// stress-ng's pipe stressor bailed ("write failed").
//
// The child reads slowly (nanosleep between reads) so the 64 KiB pipe fills
// while the parent is still writing a 256 KiB total. If write() ever returns 0
// (the old bug) the test fails immediately; with blocking writes it always
// makes progress and all 256 KiB round-trip. Success token "pipeblk-ok".
//
// Build: see REGEN_pipeblk_smoke.sh (musl-gcc, PIE).
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

static void w(const char *m) { write(1, m, strlen(m)); }

#define TOTAL (256 * 1024)

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) { w("pipeblk-fail: pipe\n"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { w("pipeblk-fail: fork\n"); return 1; }

    if (pid == 0) {
        // Child: the SLOW reader. Drain byte-by-chunk with a pause so the
        // pipe fills and the parent's write must block.
        close(fds[1]);
        size_t got = 0;
        char b[4096];
        struct timespec ts = {0, 1 * 1000 * 1000}; // 1 ms
        while (got < TOTAL) {
            ssize_t r = read(fds[0], b, sizeof(b));
            if (r <= 0) break;
            got += (size_t)r;
            nanosleep(&ts, NULL);
        }
        _exit(got == TOTAL ? 0 : 1);
    }

    // Parent: the writer. Push TOTAL bytes; a full-pipe write must block
    // (return > 0 once room frees), never hand back a spurious 0.
    close(fds[0]);
    char *buf = malloc(TOTAL);
    if (!buf) { w("pipeblk-fail: malloc\n"); return 1; }
    memset(buf, 'A', TOTAL);
    size_t sent = 0;
    while (sent < TOTAL) {
        ssize_t n = write(fds[1], buf + sent, TOTAL - sent);
        if (n < 0) { w("pipeblk-fail: write error\n"); return 1; }
        if (n == 0) { w("pipeblk-fail: write returned 0 (no block)\n"); return 1; }
        sent += (size_t)n;
    }
    close(fds[1]);

    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        w("pipeblk-ok\n");
        return 0;
    }
    w("pipeblk-fail: child incomplete\n");
    return 1;
}
