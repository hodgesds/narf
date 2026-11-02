/* SPDX-License-Identifier: MIT */
/* Bound capture writes without per-line reads or shell printf's tiny writes. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define CAPACITY 16384
#define FLUSH_NS UINT64_C(2000000000)

static volatile sig_atomic_t stopping;

static void stop(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static int monotonic_ns(uint64_t *result) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    *result = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return 0;
}

static int publish(const unsigned char *data, size_t length) {
    while (length) {
        ssize_t count = write(STDOUT_FILENO, data, length);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (!count) {
            errno = EIO;
            return -1;
        }
        data += count;
        length -= (size_t)count;
    }
    return 0;
}

int main(void) {
    unsigned char buffer[CAPACITY];
    size_t used = 0;
    uint64_t deadline = 0;
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    sigset_t blocked, wait_mask;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGINT);
    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0 ||
        sigprocmask(SIG_BLOCK, &blocked, &wait_mask) < 0) {
        perror("capture stream signal setup");
        return 1;
    }
    sigdelset(&wait_mask, SIGTERM);
    sigdelset(&wait_mask, SIGINT);

    while (!stopping) {
        struct timespec timeout, *limit = NULL;
        uint64_t now;
        if (used) {
            if (monotonic_ns(&now) < 0)
                goto fail;
            if (used == CAPACITY || now >= deadline) {
                if (publish(buffer, used) < 0)
                    goto fail;
                used = 0;
                continue;
            }
            timeout.tv_sec = (time_t)((deadline - now) / UINT64_C(1000000000));
            timeout.tv_nsec = (long)((deadline - now) % UINT64_C(1000000000));
            limit = &timeout;
        }
        struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
        /* Atomically unblock stop signals while waiting, so a signal in
         * the check-to-wait window cannot strand an idle helper forever. */
        int ready = ppoll(&input, 1, limit, &wait_mask);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        if (!ready)
            continue;
        if (input.revents & POLLNVAL) {
            errno = EBADF;
            goto fail;
        }
        if (input.revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t count = read(STDIN_FILENO, buffer + used, CAPACITY - used);
            if (count < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                goto fail;
            }
            if (!count)
                break;
            if (!used) {
                if (monotonic_ns(&now) < 0)
                    goto fail;
                deadline = now + FLUSH_NS;
            }
            used += (size_t)count;
        }
    }
    if (publish(buffer, used) < 0)
        goto fail;
    return 0;

fail:
    perror("capture stream");
    return 1;
}
