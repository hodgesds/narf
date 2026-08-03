// End-to-end fork(2) + blocking pipe-read regressions.
//
// These cases deliberately make the parent enter read(2) while the pipe is
// empty and the child still owns the last write end.  This exercises the full
// syscall -> own-stack park -> readiness wake -> restarted-read path, rather
// than finding data (or EOF) already pending:
//
//   1. The delayed child writes one byte and closes its writer.  The blocked
//      parent must wake and read exactly that byte.
//   2. The delayed child exits without writing or explicitly closing its
//      writer.  Exit-time fd teardown must wake the parent, whose read returns
//      the Linux/POSIX EOF result, 0.
//
// Success token: "fork-ok".
// Build: see REGEN_fork_pipe_smoke.sh (musl-gcc, PIE).
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

static void w(const char *msg) {
    write(STDOUT_FILENO, msg, strlen(msg));
}

static void delay_child(void) {
    // Give the parent ample time to close its writer and park in read(2),
    // including when the child is scheduled concurrently on another CPU.
    const struct timespec delay = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&delay, NULL);
}

static int wait_for_clean_exit(pid_t child, int expected_status) {
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == expected_status;
}

static int delayed_byte_round_trip(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        w("fork-fail: data pipe\n");
        return 0;
    }

    pid_t child = fork();
    if (child < 0) {
        w("fork-fail: data fork\n");
        return 0;
    }
    if (child == 0) {
        close(pipefd[0]);
        delay_child();
        const char byte = 'K';
        if (write(pipefd[1], &byte, 1) != 1) {
            _exit(40);
        }
        close(pipefd[1]);
        _exit(42);
    }

    close(pipefd[1]);
    char byte = 0;
    // The child is delayed, so this read reaches the empty-open blocking path.
    ssize_t nread = read(pipefd[0], &byte, 1);
    close(pipefd[0]);
    int child_ok = wait_for_clean_exit(child, 42);
    if (nread != 1 || byte != 'K') {
        w("fork-fail: blocked read did not receive byte\n");
        return 0;
    }
    if (!child_ok) {
        w("fork-fail: data child status\n");
        return 0;
    }
    return 1;
}

static int delayed_exit_reports_eof(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        w("fork-fail: eof pipe\n");
        return 0;
    }

    pid_t child = fork();
    if (child < 0) {
        w("fork-fail: eof fork\n");
        return 0;
    }
    if (child == 0) {
        close(pipefd[0]);
        delay_child();
        // Keep pipefd[1] open: process-exit fd teardown must drop the last
        // writer and wake the blocked parent.
        _exit(0);
    }

    close(pipefd[1]);
    char byte = 0;
    ssize_t nread = read(pipefd[0], &byte, 1);
    close(pipefd[0]);
    int child_ok = wait_for_clean_exit(child, 0);
    if (nread != 0) {
        w("fork-fail: blocked read did not receive EOF\n");
        return 0;
    }
    if (!child_ok) {
        w("fork-fail: eof child status\n");
        return 0;
    }
    return 1;
}

int main(void) {
    if (!delayed_byte_round_trip()) {
        return 1;
    }
    if (!delayed_exit_reports_eof()) {
        return 1;
    }
    w("fork-ok\n");
    return 0;
}
