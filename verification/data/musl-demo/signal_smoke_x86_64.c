#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <errno.h>

static void w(const char *msg) {
    write(1, msg, strlen(msg));
}

volatile int got_signal = 0;

void handler(int sig) {
    got_signal = 1;
    write(1, "in-handler\n", 11);
    syscall(301, 76, sig); // beacon::paint(76, sig)
}

int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) { w("signal-fail: sigaction\n"); return 1; }

    w("signal-raise...\n");
    char id_msg[128];
    snprintf(id_msg, sizeof(id_msg), "pid=%d, tid=%d, handler=%p\n", (int)getpid(), (int)syscall(186), handler);
    w(id_msg);
    long tid = syscall(186);
    int res = syscall(200, tid, SIGUSR1);
    if (res != 0) {
        char fail_msg[64];
        snprintf(fail_msg, sizeof(fail_msg), "signal-fail: tkill returned %d, errno=%d\n", res, errno);
        w(fail_msg);
        return 1;
    }
    w("tkill-ok, pausing...\n");

    pause();
    w("pause-returned\n");

    if (got_signal) {
        w("signal-ok\n");
    } else {
        w("signal-fail: pause returned without signal\n");
    }

    return 0;
}
