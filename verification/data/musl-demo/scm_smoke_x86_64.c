/* AF_UNIX SCM_RIGHTS fd-passing smoke for the NARF linux-compat demo.
 *
 * The foundational Wayland transport primitive: a compositor and its
 * clients pass shm / dma-buf fds over the Wayland socket via
 * sendmsg/recvmsg + SCM_RIGHTS ancillary data. This proves NARF's
 * AF_UNIX sockets carry fds end-to-end.
 *
 * Flow:
 *   1. socketpair(AF_UNIX, SOCK_STREAM)
 *   2. sendmsg(sv[0], 1 data byte + SCM_RIGHTS=[fd 1 (stdout)])
 *   3. recvmsg(sv[1], ...) — recover the passed fd
 *   4. write(received_fd, "scm-ok\n") — the received fd is a working dup
 *      of stdout, so the token lands on the console.
 *
 * Any failed step prints "scm-fail-<step>". The success token `scm-ok`
 * is emitted THROUGH the passed fd, so it only appears if fd-passing
 * actually works.
 */

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>

static void w(const char *s) {
    write(1, s, strlen(s));
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        w("scm-fail-socketpair\n");
        return 1;
    }

    char data = 'x';
    struct iovec iov = {&data, 1};
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);

    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    int sendfd = 1; /* stdout */
    memcpy(CMSG_DATA(c), &sendfd, sizeof(int));

    if (sendmsg(sv[0], &msg, 0) < 0) {
        w("scm-fail-sendmsg\n");
        return 1;
    }

    char rdata = 0;
    struct iovec riov = {&rdata, 1};
    char rcbuf[CMSG_SPACE(sizeof(int))];
    memset(rcbuf, 0, sizeof rcbuf);

    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof rmsg);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    rmsg.msg_control = rcbuf;
    rmsg.msg_controllen = sizeof rcbuf;

    if (recvmsg(sv[1], &rmsg, 0) < 0) {
        w("scm-fail-recvmsg\n");
        return 1;
    }

    struct cmsghdr *rc = CMSG_FIRSTHDR(&rmsg);
    if (!rc || rc->cmsg_level != SOL_SOCKET || rc->cmsg_type != SCM_RIGHTS) {
        w("scm-fail-nocmsg\n");
        return 1;
    }
    int gotfd = -1;
    memcpy(&gotfd, CMSG_DATA(rc), sizeof(int));
    if (gotfd < 0) {
        w("scm-fail-badfd\n");
        return 1;
    }

    /* Write the success token THROUGH the received fd. */
    const char *m = "scm-ok\n";
    if (write(gotfd, m, 7) != 7) {
        w("scm-fail-write\n");
        return 1;
    }
    return 0;
}
