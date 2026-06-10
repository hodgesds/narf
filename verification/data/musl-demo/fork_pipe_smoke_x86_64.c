#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

static void w(const char *msg) {
    write(1, msg, strlen(msg));
}

int main() {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        w("fork-fail: pipe\n");
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        w("fork-fail: fork\n");
        return 1;
    }

    if (pid == 0) {
        // Child
        close(pipefd[0]); // Close unused read end
        char *msg = "hello from child";
        write(pipefd[1], msg, strlen(msg));
        close(pipefd[1]);
        exit(42);
    } else {
        // Parent
        close(pipefd[1]); // Close unused write end

        int wstatus;
        if (waitpid(pid, &wstatus, 0) == -1) {
            w("fork-fail: waitpid\n");
            return 1;
        }

        char buf[32];
        memset(buf, 0, sizeof(buf));
        read(pipefd[0], buf, sizeof(buf) - 1);
        close(pipefd[0]);

        if (strcmp(buf, "hello from child") != 0) {
            w("fork-fail: bad msg\n");
            return 1;
        }

        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 42) {
            w("fork-ok\n");
        } else {
            char fail_msg[64];
            snprintf(fail_msg, sizeof(fail_msg), "fork-fail: bad exit status 0x%08x\n", wstatus);
            w(fail_msg);
        }
    }
    return 0;
}
