// sendmmsg(2) + recvmmsg(2) smoke. Over an AF_UNIX stream socketpair,
// send two 2-byte messages in one sendmmsg, then receive them back in
// one recvmmsg (each recv buffer sized to one message so the stream
// splits cleanly). Success token "mmsg-ok".
//
// Build: see REGEN_mmsg_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static void w(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        w("mmsg-fail: socketpair\n");
        return 1;
    }

    char m0[2] = {'a', 'a'}, m1[2] = {'b', 'b'};
    struct iovec siov[2] = {{m0, 2}, {m1, 2}};
    struct mmsghdr smsgs[2];
    memset(smsgs, 0, sizeof smsgs);
    smsgs[0].msg_hdr.msg_iov = &siov[0];
    smsgs[0].msg_hdr.msg_iovlen = 1;
    smsgs[1].msg_hdr.msg_iov = &siov[1];
    smsgs[1].msg_hdr.msg_iovlen = 1;
    int ns = sendmmsg(sv[0], smsgs, 2, 0);
    if (ns != 2) {
        w("mmsg-fail: sendmmsg\n");
        return 1;
    }

    char b0[2] = {0}, b1[2] = {0};
    struct iovec riov[2] = {{b0, 2}, {b1, 2}};
    struct mmsghdr rmsgs[2];
    memset(rmsgs, 0, sizeof rmsgs);
    rmsgs[0].msg_hdr.msg_iov = &riov[0];
    rmsgs[0].msg_hdr.msg_iovlen = 1;
    rmsgs[1].msg_hdr.msg_iov = &riov[1];
    rmsgs[1].msg_hdr.msg_iovlen = 1;
    int nr = recvmmsg(sv[1], rmsgs, 2, 0, NULL);
    if (nr != 2) {
        w("mmsg-fail: recvmmsg\n");
        return 1;
    }

    if (memcmp(b0, "aa", 2) == 0 && memcmp(b1, "bb", 2) == 0) {
        w("mmsg-ok\n");
    } else {
        w("mmsg-fail: data\n");
    }
    close(sv[0]);
    close(sv[1]);
    return 0;
}
