/* AF_UNIX blocking serve smoke — regression for a blocking recv on a unix
 * socket returning a spurious EOF instead of waiting for data.
 *
 * A server that accept()s then read()s a request directly (rather than poll()ing
 * first, as libwayland/weston do) used to get read()==0 the instant the rx ring
 * was empty: `read` mapped the empty-ring `WouldBlock` to `Ok(0)`, and the
 * socket didn't override `read_should_block()` (default false), so `sys_read`
 * treated the empty-but-open ring as end-of-file and the server saw "client
 * closed" and gave up. (libwayland masks it by reading only after poll reports
 * the fd readable.) This reproduces it directly:
 *   - parent: bind+listen, BLOCKING accept(), then BLOCKING read(),
 *   - child: connect, then (after a delay) write "PING".
 * read() MUST return the 4 PING bytes, not EOF. `alarm(8)` bounds a hang.
 * Success token: `uxe-ok`.
 */
#define _GNU_SOURCE 1
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static const char *SOCKPATH = "/tmp/uxe.sock";

static void on_alarm(int sig) {
    (void)sig;
    const char *m = "uxe-fail: blocking recv hung (read_should_block?)\n";
    (void)!write(1, m, strlen(m));
    _exit(1);
}

int main(void) {
    signal(SIGALRM, on_alarm);
    alarm(8); /* the pre-fix bug hangs forever; bound it */

    unlink(SOCKPATH);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKPATH, sizeof addr.sun_path - 1);
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) {
        write(1, "uxe-fail: bind\n", 15);
        return 1;
    }
    if (listen(srv, 4) != 0) {
        write(1, "uxe-fail: listen\n", 17);
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        usleep(150000); /* let the parent reach the blocking accept() */
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *)&addr, sizeof addr) == 0) {
            usleep(150000); /* let the parent reach the blocking read() */
            (void)!write(c, "PING", 4);
            usleep(400000);
        }
        _exit(0);
    }

    /* BLOCKING accept — parks until the child connects. The pre-fix bug: the
     * AF_UNIX connect wakes this task but doesn't advance the readiness
     * generation, so the accept park's lost-wake guard never fires and it
     * re-parks forever (its deadline is far-future). */
    int conn = accept(srv, NULL, NULL);
    if (conn < 0) {
        write(1, "uxe-fail: accept\n", 17);
        return 1;
    }
    /* BLOCKING read — parks until the child writes; same break-out path. */
    char buf[8] = {0};
    int r = (int)read(conn, buf, sizeof buf);
    if (r == 4 && memcmp(buf, "PING", 4) == 0) {
        alarm(0);
        write(1, "uxe-ok\n", 7);
        return 0;
    }
    char b[64];
    int n = snprintf(b, sizeof b, "uxe-fail: r=%d\n", r);
    (void)!write(1, b, n);
    return 1;
}
