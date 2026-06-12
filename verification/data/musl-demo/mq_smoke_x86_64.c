// POSIX message-queue smoke. Open a named queue with explicit attrs,
// send two messages at different priorities, confirm getattr reports the
// queue state, then receive them highest-priority-first. Success token
// "mq-ok".
//
// Build: see REGEN_mq_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <mqueue.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    const char *name = "/narfmq";
    mq_unlink(name); // best-effort clean slate

    struct mq_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.mq_maxmsg = 4;
    attr.mq_msgsize = 64;
    mqd_t q = mq_open(name, O_CREAT | O_RDWR, 0644, &attr);
    if (q == (mqd_t)-1) { w("mq-fail: open\n"); return 1; }

    if (mq_send(q, "alpha", 5, 1) != 0) { w("mq-fail: send1\n"); return 1; }
    if (mq_send(q, "bravo", 5, 9) != 0) { w("mq-fail: send2\n"); return 1; }

    struct mq_attr cur;
    memset(&cur, 0, sizeof cur);
    if (mq_getattr(q, &cur) != 0) { w("mq-fail: getattr\n"); return 1; }
    if (cur.mq_curmsgs != 2 || cur.mq_maxmsg != 4 || cur.mq_msgsize != 64) {
        w("mq-fail: attr\n"); return 1;
    }

    // Highest priority first: bravo (9) before alpha (1).
    char buf[64];
    unsigned int prio = 0;
    ssize_t n = mq_receive(q, buf, sizeof buf, &prio);
    if (n != 5 || memcmp(buf, "bravo", 5) != 0 || prio != 9) { w("mq-fail: recv1\n"); return 1; }
    n = mq_receive(q, buf, sizeof buf, &prio);
    if (n != 5 || memcmp(buf, "alpha", 5) != 0 || prio != 1) { w("mq-fail: recv2\n"); return 1; }

    mq_close(q);
    if (mq_unlink(name) != 0) { w("mq-fail: unlink\n"); return 1; }

    w("mq-ok\n");
    return 0;
}
