// eventfd(2) smoke. Exercises the eventfd2 syscall end-to-end via a
// real musl binary: create a counter eventfd, write a value, read it
// back, and verify the counter semantics. It then repeats the Qt/glib
// wakeup shape: a remote CPU writes a shared eventfd while the main CPU
// is parked in epoll_wait(-1). Success token "eventfd-ok".
//
// Build: see REGEN_eventfd_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE 1
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define ROUNDS 64

static void w(const char *m) { write(1, m, strlen(m)); }

static void alarm_handler(int sig) {
    (void)sig;
    w("eventfd-fail: timeout\n");
    _exit(1);
}

static int pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

struct wake_args {
    int eventfd;
    int gate;
};

static void *remote_wake(void *opaque) {
    const struct wake_args *args = opaque;
    char start;
    if (pin_to_cpu(1) != 0 || read(args->gate, &start, 1) != 1)
        return (void *)2;
    uint64_t one = 1;
    if (write(args->eventfd, &one, sizeof one) != (ssize_t)sizeof one)
        return (void *)3;
    return 0;
}

int main(void) {
    signal(SIGALRM, alarm_handler);
    alarm(20);

    int fd = eventfd(0, 0);
    if (fd < 0) {
        w("eventfd-fail: create\n");
        return 1;
    }
    // Add 5 to the counter, then read it back. A non-semaphore
    // eventfd read returns the whole counter and resets it to 0.
    uint64_t v = 5;
    if (write(fd, &v, sizeof v) != (ssize_t)sizeof v) {
        w("eventfd-fail: write\n");
        return 1;
    }
    uint64_t r = 0;
    if (read(fd, &r, sizeof r) != (ssize_t)sizeof r) {
        w("eventfd-fail: read\n");
        return 1;
    }
    if (r != 5) {
        w("eventfd-fail: value\n");
        return 1;
    }

    if (pin_to_cpu(0) != 0) {
        w("eventfd-fail: CPU 0 affinity\n");
        return 1;
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event interest = {
        .events = EPOLLIN,
        .data.fd = fd,
    };
    if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &interest) != 0) {
        w("eventfd-fail: epoll setup\n");
        return 1;
    }

    for (int round = 0; round < ROUNDS; round++) {
        int gate[2];
        if (pipe2(gate, O_CLOEXEC) != 0) {
            w("eventfd-fail: pipe\n");
            return 1;
        }
        struct wake_args args = { .eventfd = fd, .gate = gate[0] };
        pthread_t worker;
        if (pthread_create(&worker, 0, remote_wake, &args) != 0) {
            w("eventfd-fail: pthread_create\n");
            return 1;
        }

        if (write(gate[1], "!", 1) != 1) {
            w("eventfd-fail: worker gate\n");
            return 1;
        }

        if ((round & 1) == 0) {
            struct epoll_event event;
            if (epoll_wait(epfd, &event, 1, -1) != 1 || event.data.fd != fd) {
                w("eventfd-fail: epoll wait\n");
                return 1;
            }
        } else {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (ppoll(&pfd, 1, 0, 0) != 1 || !(pfd.revents & POLLIN)) {
                w("eventfd-fail: ppoll wait\n");
                return 1;
            }
        }
        r = 0;
        if (read(fd, &r, sizeof r) != (ssize_t)sizeof r || r != 1) {
            w("eventfd-fail: epoll read\n");
            return 1;
        }
        void *worker_result = 0;
        if (pthread_join(worker, &worker_result) != 0 || worker_result != 0) {
            w("eventfd-fail: worker exit\n");
            return 1;
        }
        close(gate[0]);
        close(gate[1]);
    }

    alarm(0);
    w("eventfd-ok\n");
    close(epfd);
    close(fd);
    return 0;
}
