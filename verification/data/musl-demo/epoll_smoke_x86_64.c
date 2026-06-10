#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>

static void w(const char *msg) {
    write(1, msg, strlen(msg));
}

int main() {
    int pipefd[2];
    if (pipe(pipefd) == -1) { w("epoll-fail: pipe\n"); return 1; }

    int epfd = epoll_create1(0);
    if (epfd == -1) { w("epoll-fail: create\n"); return 1; }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev) == -1) {
        w("epoll-fail: ctl\n"); return 1;
    }

    pid_t pid = fork();
    if (pid == -1) { w("epoll-fail: fork\n"); return 1; }

    if (pid == 0) {
        // Child
        close(pipefd[0]);
        w("child-writing\n");
        write(pipefd[1], "wake", 4);
        exit(0);
    } else {
        // Parent
        struct epoll_event events[1];
        int nfds = epoll_wait(epfd, events, 1, 5000); // 5 sec timeout
        
        if (nfds == 1 && events[0].data.fd == pipefd[0]) {
            char buf[16] = {0};
            read(pipefd[0], buf, sizeof(buf));
            if (strcmp(buf, "wake") == 0) {
                w("epoll-ok\n");
            } else {
                w("epoll-fail: bad read\n");
            }
        } else {
            char fail_msg[64];
            snprintf(fail_msg, sizeof(fail_msg), "epoll-fail: nfds=%d, errno=%d\n", nfds, errno);
            w(fail_msg);
        }
        waitpid(pid, NULL, 0);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    return 0;
}
