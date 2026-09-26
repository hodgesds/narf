// A blocking FIFO open must be interruptible by a signal. fifo(7): an
// O_RDONLY open with no writer sleeps in wait_for_partner, which Linux
// makes interruptible — a caught signal aborts the open with -EINTR
// (sa_flags without SA_RESTART). This is exactly the shape stress-ng's
// --dup dup2-race helper leans on: it arms a 1 ms ITIMER_REAL and relies
// on SIGALRM to EINTR its writer-less FIFO open every cycle. A kernel
// that instead restarts the open unconditionally turns each 1 ms cycle
// into an unbounded park. Success token "fifoeintr-ok".
//
// Second half re-checks the rendezvous still works: with a writer child,
// the same blocking open must SUCCEED, not EINTR — the signal check must
// not shadow a peer that has already appeared.
//
// Build: see REGEN_fifoeintr_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>

static volatile sig_atomic_t alarms = 0;
static void on_alarm(int sig) { (void)sig; alarms++; }

static void w(const char *m) { write(1, m, strlen(m)); }

static double now_s(void) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

int main(void) {
    const char *path = "/tmp/fifoeintr.fifo";
    (void)unlink(path);
    if (mkfifo(path, 0600) != 0) {
        w("fifoeintr-fail: mkfifo\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm; // sa_flags = 0: NO SA_RESTART — open must EINTR.
    if (sigaction(SIGALRM, &sa, 0) != 0) {
        w("fifoeintr-fail: sigaction\n");
        return 1;
    }

    // Repeating 20 ms timer (repeating, not one-shot, so a raise that lands
    // before the park still gets a later chance instead of wedging).
    struct itimerval it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = 20000;
    it.it_interval.tv_usec = 20000;
    if (setitimer(ITIMER_REAL, &it, 0) != 0) {
        w("fifoeintr-fail: setitimer\n");
        return 1;
    }

    // 1. Writer-less blocking open: must return -1/EINTR, promptly (the
    //    first or second 20 ms tick), never hand back a valid fd.
    double t0 = now_s();
    int fd = open(path, O_RDONLY);
    double dt = now_s() - t0;
    struct itimerval off;
    memset(&off, 0, sizeof off);
    setitimer(ITIMER_REAL, &off, 0);
    if (fd >= 0) {
        w("fifoeintr-fail: writer-less open returned an fd\n");
        return 1;
    }
    if (errno != EINTR) {
        char buf[96];
        snprintf(buf, sizeof buf, "fifoeintr-fail: errno %d not EINTR\n", errno);
        w(buf);
        return 1;
    }
    if (dt > 2.0) {
        char buf[96];
        snprintf(buf, sizeof buf, "fifoeintr-fail: EINTR after %.3fs (>2s)\n", dt);
        w(buf);
        return 1;
    }

    // 2. Rendezvous intact: a writer child makes the same open succeed.
    pid_t pid = fork();
    if (pid < 0) {
        w("fifoeintr-fail: fork\n");
        return 1;
    }
    if (pid == 0) {
        int wfd = open(path, O_WRONLY);
        if (wfd < 0)
            _exit(1);
        (void)write(wfd, "x", 1);
        (void)close(wfd);
        _exit(0);
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        w("fifoeintr-fail: open with writer\n");
        return 1;
    }
    char c;
    ssize_t r = read(fd, &c, 1);
    (void)close(fd);
    int st = 0;
    (void)waitpid(pid, &st, 0);
    (void)unlink(path);
    if (r != 1 || c != 'x' || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        w("fifoeintr-fail: rendezvous read\n");
        return 1;
    }
    w("fifoeintr-ok\n");
    return 0;
}
