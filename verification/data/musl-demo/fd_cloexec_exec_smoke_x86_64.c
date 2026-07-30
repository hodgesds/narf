// Exercise the dbus-run-session fd handoff shape:
//
//   close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)
//   fcntl(writer, F_SETFD, 0)
//   execve(child)
//
// The exec'd child must retain only the explicitly cleared writer and the
// parent must observe its byte rather than premature EOF.  Success token:
// "fd-cloexec-exec-ok".
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_main(const char *fd_text) {
    char *end = NULL;
    long fd = strtol(fd_text, &end, 10);
    if (!end || *end || fd < 0 || fd > INT_MAX)
        return 20;
    return write((int)fd, "R", 1) == 1 ? 0 : 21;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--child") == 0)
        return child_main(argv[2]);

    int p[2];
    if (pipe(p) != 0) {
        puts("fd-cloexec-exec-fail: pipe");
        return 1;
    }
    pid_t child = fork();
    if (child < 0) {
        puts("fd-cloexec-exec-fail: fork");
        return 1;
    }
    if (child == 0) {
        char fd_text[16];
        close(p[0]);
        if (syscall(SYS_close_range, 3U, UINT_MAX, 1U << 2) != 0)
            _exit(2);
        if (fcntl(p[1], F_GETFD) != FD_CLOEXEC ||
            fcntl(p[1], F_SETFD, 0) != 0 ||
            fcntl(p[1], F_GETFD) != 0)
            _exit(3);
        snprintf(fd_text, sizeof(fd_text), "%d", p[1]);
        execl("/bin/fd_cloexec_exec_smoke", "fd_cloexec_exec_smoke",
              "--child", fd_text, (char *)NULL);
        _exit(4);
    }

    close(p[1]);
    char byte = 0;
    int status = 0;
    int ok = read(p[0], &byte, 1) == 1 && byte == 'R' &&
             waitpid(child, &status, 0) == child && WIFEXITED(status) &&
             WEXITSTATUS(status) == 0;
    close(p[0]);
    if (!ok) {
        puts("fd-cloexec-exec-fail: handoff");
        return 1;
    }
    puts("fd-cloexec-exec-ok");
    return 0;
}
