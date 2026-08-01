/*
 * Concurrent fork(2) -> execve(2) SMP regression.
 *
 * Early systemd starts several services at once.  Each child inherits a
 * fully-populated process image, may run on another CPU immediately, and
 * replaces that image with execve while PID 1 waits for completions.  The
 * one-at-a-time fork and CLOEXEC smokes do not cover races in publication,
 * address-space replacement, descriptor inheritance, exit notification, or
 * reaping across that burst.
 *
 * Sixteen children block behind one pipe EOF gate, become runnable together,
 * then self-exec at once.  A single explicitly selected pipe descriptor
 * survives CLOEXEC and carries an atomic identity record (including getcpu)
 * back to the parent.  Eight complete rounds exercise 128
 * fork/exec/exit/reap transitions and must observe execution on more than one
 * CPU.
 *
 * Success token: fork-exec-burst-ok.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUNDS 8
#define CHILDREN 16

struct child_record {
    uint32_t round;
    uint32_t slot;
    int32_t pid;
    uint32_t cpu;
    uint32_t magic;
};

static const uint32_t RECORD_MAGIC = 0xf07eec42U;

static void fail(const char *why) {
    (void)!write(STDOUT_FILENO, why, strlen(why));
}

static void alarm_handler(int sig) {
    (void)sig;
    fail("fork-exec-burst-fail: timeout\n");
    _exit(1);
}

static int parse_u32(const char *text, uint32_t *value) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX)
        return -1;
    *value = (uint32_t)parsed;
    return 0;
}

static int child_main(const char *round_text, const char *slot_text,
                      const char *fd_text) {
    uint32_t round;
    uint32_t slot;
    uint32_t fd;
    if (parse_u32(round_text, &round) != 0 ||
        parse_u32(slot_text, &slot) != 0 ||
        parse_u32(fd_text, &fd) != 0 || fd > INT32_MAX)
        return 20;

    unsigned cpu = UINT32_MAX;
    unsigned node = UINT32_MAX;
    if (syscall(SYS_getcpu, &cpu, &node, NULL) != 0)
        return 21;

    struct child_record record = {
        .round = round,
        .slot = slot,
        .pid = (int32_t)getpid(),
        .cpu = cpu,
        .magic = RECORD_MAGIC,
    };
    return write((int)fd, &record, sizeof(record)) == (ssize_t)sizeof(record)
               ? 0
               : 22;
}

static int read_record(int fd, struct child_record *record) {
    unsigned char *out = (unsigned char *)record;
    size_t done = 0;
    while (done < sizeof(*record)) {
        ssize_t n = read(fd, out + done, sizeof(*record) - done);
        if (n > 0) {
            done += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "--child") == 0)
        return child_main(argv[2], argv[3], argv[4]);

    signal(SIGALRM, alarm_handler);
    alarm(60);

    unsigned parent_cpu = UINT32_MAX;
    unsigned parent_node = UINT32_MAX;
    if (syscall(SYS_getcpu, &parent_cpu, &parent_node, NULL) != 0 ||
        parent_cpu >= 64) {
        fail("fork-exec-burst-fail: getcpu\n");
        return 1;
    }
    uint64_t seen_cpus = 1ULL << parent_cpu;

    for (uint32_t round = 0; round < ROUNDS; round++) {
        int gate[2];
        int results[2];
        pid_t pids[CHILDREN];
        if (pipe2(gate, O_CLOEXEC) != 0 ||
            pipe2(results, O_CLOEXEC) != 0) {
            fail("fork-exec-burst-fail: pipe\n");
            return 1;
        }

        for (uint32_t slot = 0; slot < CHILDREN; slot++) {
            pid_t child = fork();
            if (child < 0) {
                fail("fork-exec-burst-fail: fork\n");
                return 1;
            }
            if (child == 0) {
                char byte;
                char round_text[16];
                char slot_text[16];
                char fd_text[16];
                close(gate[1]);
                close(results[0]);
                if (read(gate[0], &byte, 1) != 0)
                    _exit(2);
                close(gate[0]);

                if (fcntl(results[1], F_SETFD, 0) != 0)
                    _exit(3);

                snprintf(round_text, sizeof(round_text), "%u", round);
                snprintf(slot_text, sizeof(slot_text), "%u", slot);
                snprintf(fd_text, sizeof(fd_text), "%d", results[1]);
                execl("/bin/fork_exec_burst_smoke",
                      "fork_exec_burst_smoke", "--child", round_text,
                      slot_text, fd_text, (char *)NULL);
                _exit(4);
            }
            pids[slot] = child;
        }

        close(gate[0]);
        close(gate[1]);
        close(results[1]);

        uint32_t seen = 0;
        for (uint32_t record_index = 0; record_index < CHILDREN;
             record_index++) {
            struct child_record record;
            if (read_record(results[0], &record) != 0 ||
                record.round != round || record.slot >= CHILDREN ||
                record.magic != RECORD_MAGIC ||
                record.cpu >= 64 ||
                record.pid != (int32_t)pids[record.slot] ||
                (seen & (1U << record.slot)) != 0) {
                fail("fork-exec-burst-fail: child record\n");
                return 1;
            }
            seen |= 1U << record.slot;
            seen_cpus |= 1ULL << record.cpu;
        }
        close(results[0]);
        if (seen != (1U << CHILDREN) - 1U) {
            fail("fork-exec-burst-fail: incomplete burst\n");
            return 1;
        }

        for (uint32_t slot = 0; slot < CHILDREN; slot++) {
            int status = 0;
            errno = 0;
            pid_t waited = waitpid(pids[slot], &status, 0);
            if (waited != pids[slot] ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                char detail[160];
                int len = snprintf(detail, sizeof(detail),
                                   "fork-exec-burst-fail: child exit "
                                   "round=%u slot=%u pid=%d waited=%d "
                                   "status=0x%x errno=%d\n",
                                   round, slot, (int)pids[slot], (int)waited,
                                   status, errno);
                if (len > 0)
                    (void)!write(STDOUT_FILENO, detail, (size_t)len);
                return 1;
            }
        }
    }

    if ((seen_cpus & (seen_cpus - 1)) == 0) {
        fail("fork-exec-burst-fail: no SMP execution\n");
        return 1;
    }

    alarm(0);
    fail("fork-exec-burst-ok\n");
    return 0;
}
