// SIGKILL ends a job-control stop, checked against Linux.
//
// A child stopped by SIGSTOP — blocked in pause(2), or stopped while running
// — must die of a later SIGKILL without a SIGCONT. On NARF a stopped child
// that had been blocked in a syscall never died: SIGKILL woke it, the
// syscall re-executed, and the exit to user mode parked it in the stop again
// before the SIGKILL was taken, so the parent's waitpid hung forever.
//
// Success token "killstopped-ok".
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void one(const char *what, int busy) {
    pid_t c = fork();
    if (c == 0) {
        if (busy)
            for (;;) __asm__ volatile("" ::: "memory");
        for (;;) pause();
    }
    usleep(100000);
    int st = 0;
    kill(c, SIGSTOP);
    if (waitpid(c, &st, WUNTRACED) != c || !WIFSTOPPED(st)) {
        printf("killstopped-fail: %s child did not stop (status %#x)\n", what, st);
        fails++;
    }
    kill(c, SIGKILL);
    st = 0;
    if (waitpid(c, &st, 0) != c || !WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) {
        printf("killstopped-fail: %s stopped child not killed by SIGKILL (status %#x)\n", what, st);
        fails++;
    }
}

static void on_alarm(int s) {
    (void)s;
    static const char m[] = "killstopped-fail: timed out (a SIGKILLed stopped child never died)\n";
    write(1, m, sizeof m - 1);
    _exit(1);
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    signal(SIGALRM, on_alarm);
    alarm(20);
    one("paused", 0);
    one("running", 1);
    if (fails == 0) printf("killstopped-ok\n");
    return fails != 0;
}
