/* systemd Type=notify SMP regression smoke.
 *
 * systemd PID 1 receives service readiness on a path-bound AF_UNIX datagram
 * socket with SO_PASSCRED, while the service is a distinct process.  On an
 * SMP boot the manager may be parked in epoll_wait(-1) on CPU 0 while the
 * service is scheduled on CPU 1.  A correct kernel must make every packet
 * wake the manager, preserve the sender's credentials, and allow the child
 * to exit/reap.  This is deliberately a live process+syscall test rather
 * than a direct FileOps test: it covers the cross-CPU own-stack park/wake
 * path used by systemd-udevd's READY=1 notification.
 *
 * Success token: notify-epoll-smp-ok.
 */
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUNDS 64
static const char *const SOCKET_PATH = "/tmp/narf-notify-epoll-smp.sock";
static const char READY[] = "READY=1\n";

static void fail(const char *why) {
    (void)!write(1, why, strlen(why));
}

static void alarm_handler(int sig) {
    (void)sig;
    fail("notify-epoll-smp-fail: timeout\n");
    _exit(1);
}

static int pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

int main(void) {
    signal(SIGALRM, alarm_handler);
    alarm(20);

    if (pin_to_cpu(0) != 0) {
        fail("notify-epoll-smp-fail: CPU 0 affinity\n");
        return 1;
    }

    unlink(SOCKET_PATH);
    int rx = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int tx = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (rx < 0 || tx < 0) {
        fail("notify-epoll-smp-fail: socket\n");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    socklen_t addr_len = (socklen_t)(sizeof(addr.sun_family) + strlen(SOCKET_PATH) + 1);
    if (bind(rx, (struct sockaddr *)&addr, addr_len) != 0) {
        fail("notify-epoll-smp-fail: bind\n");
        return 1;
    }
    int one = 1;
    if (setsockopt(rx, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) != 0) {
        fail("notify-epoll-smp-fail: SO_PASSCRED\n");
        return 1;
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event interest;
    memset(&interest, 0, sizeof(interest));
    interest.events = EPOLLIN;
    interest.data.fd = rx;
    if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, rx, &interest) != 0) {
        fail("notify-epoll-smp-fail: epoll setup\n");
        return 1;
    }

    for (int round = 0; round < ROUNDS; round++) {
        int gate[2];
        if (pipe2(gate, O_CLOEXEC) != 0) {
            fail("notify-epoll-smp-fail: pipe\n");
            return 1;
        }
        pid_t child = fork();
        if (child < 0) {
            fail("notify-epoll-smp-fail: fork\n");
            return 1;
        }
        if (child == 0) {
            char start;
            close(gate[1]);
            // systemd-udevd has PrivateMounts=yes. The notify socket inode
            // stays visible through this cloned mount tree, while the sender
            // is nevertheless a distinct process on the remote CPU.
            if (pin_to_cpu(1) != 0 || unshare(CLONE_NEWNS) != 0 ||
                read(gate[0], &start, 1) != 1) {
                _exit(2);
            }
            struct iovec iov = { .iov_base = (void *)READY, .iov_len = sizeof(READY) - 1 };
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &addr;
            msg.msg_namelen = addr_len;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            _exit(sendmsg(tx, &msg, 0) == (ssize_t)(sizeof(READY) - 1) ? 0 : 3);
        }

        close(gate[0]);
        if (write(gate[1], "!", 1) != 1) {
            fail("notify-epoll-smp-fail: child gate\n");
            return 1;
        }
        close(gate[1]);

        struct epoll_event event;
        if (epoll_wait(epfd, &event, 1, -1) != 1 || event.data.fd != rx) {
            fail("notify-epoll-smp-fail: epoll wait\n");
            return 1;
        }
        char packet[32] = {0};
        char control[CMSG_SPACE(sizeof(struct ucred))];
        struct iovec iov = { .iov_base = packet, .iov_len = sizeof(packet) };
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        memset(control, 0, sizeof(control));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        if (recvmsg(rx, &msg, 0) != (ssize_t)(sizeof(READY) - 1) ||
            memcmp(packet, READY, sizeof(READY) - 1) != 0) {
            fail("notify-epoll-smp-fail: recv READY\n");
            return 1;
        }
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_CREDENTIALS ||
            ((struct ucred *)CMSG_DATA(cmsg))->pid != child) {
            fail("notify-epoll-smp-fail: credentials\n");
            return 1;
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fail("notify-epoll-smp-fail: child exit\n");
            return 1;
        }
    }

    alarm(0);
    unlink(SOCKET_PATH);
    fail("notify-epoll-smp-ok\n");
    return 0;
}
