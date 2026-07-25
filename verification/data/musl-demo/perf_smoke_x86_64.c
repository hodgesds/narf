#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <string.h>

#define PERF_TYPE_HARDWARE 0
#define PERF_COUNT_HW_CPU_CYCLES 0
#define PERF_FORMAT_TOTAL_TIME_ENABLED (1ULL << 0)
#define PERF_FORMAT_TOTAL_TIME_RUNNING (1ULL << 1)
#define PERF_FORMAT_ID (1ULL << 2)
#define PERF_FORMAT_GROUP (1ULL << 3)
#define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO('$', 1)
#define PERF_EVENT_IOC_RESET _IO('$', 3)
#define PERF_EVENT_IOC_ID _IOR('$', 7, uint64_t *)
#define PERF_IOC_FLAG_GROUP 1

struct perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period_or_freq;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events_or_watermark;
    uint32_t bp_type;
    uint64_t bp_addr_or_config1;
    uint64_t bp_len_or_config2;
    uint64_t branch_sample_type;
    uint64_t sample_regs_user;
    uint32_t sample_stack_user;
    int32_t clockid;
    uint64_t sample_regs_intr;
    uint32_t aux_watermark;
    uint16_t sample_max_stack;
    uint16_t __reserved_2;
    uint32_t aux_sample_size;
    uint32_t __reserved_3;
    uint64_t sig_data;
};

// Helper to invoke perf_event_open
long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                     int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                       PERF_FORMAT_TOTAL_TIME_RUNNING |
                       PERF_FORMAT_ID;
    attr.flags = 1; // disabled

    long fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("perf_smoke: ERROR - perf_event_open failed with %ld\n", fd);
        return 1;
    }

    uint64_t id = 0;
    if (ioctl(fd, PERF_EVENT_IOC_ID, &id) != 0 || id == 0 ||
        ioctl(fd, PERF_EVENT_IOC_RESET, 0) != 0 ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        printf("perf_smoke: ERROR - control ioctl failed\n");
        close(fd);
        return 1;
    }

    // Do some arbitrary loop to consume cycles
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++) {
        dummy += i;
    }

    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) != 0) {
        printf("perf_smoke: ERROR - disable ioctl failed\n");
        close(fd);
        return 1;
    }

    uint64_t stat[4] = {0};
    if (read(fd, stat, sizeof(stat)) != sizeof(stat)) {
        printf("perf_smoke: ERROR - stat-format read failed\n");
        close(fd);
        return 1;
    }
    if (stat[0] == 0 || stat[1] == 0 || stat[2] == 0 ||
        stat[1] != stat[2] || stat[3] != id) {
        printf("perf_smoke: ERROR - invalid stat record %llu/%llu/%llu/%llu\n",
               (unsigned long long)stat[0], (unsigned long long)stat[1],
               (unsigned long long)stat[2], (unsigned long long)stat[3]);
        close(fd);
        return 1;
    }
    printf("perf_smoke: cycles delta %llu\n", (unsigned long long)stat[0]);
    close(fd);

    // Exercise a real two-member software event group.
    struct perf_event_attr group_attr;
    memset(&group_attr, 0, sizeof(group_attr));
    group_attr.type = 1; // PERF_TYPE_SOFTWARE
    group_attr.size = sizeof(group_attr);
    group_attr.config = 0; // PERF_COUNT_SW_CPU_CLOCK
    group_attr.read_format = PERF_FORMAT_GROUP |
                             PERF_FORMAT_TOTAL_TIME_ENABLED |
                             PERF_FORMAT_TOTAL_TIME_RUNNING |
                             PERF_FORMAT_ID;
    group_attr.flags = 1; // disabled
    long group_fd = perf_event_open(&group_attr, 0, -1, -1, 0);
    group_attr.config = 1; // PERF_COUNT_SW_TASK_CLOCK
    long member_fd = perf_event_open(&group_attr, 0, -1, group_fd, 0);
    if (group_fd < 0 || member_fd < 0 ||
        ioctl(group_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0 ||
        ioctl(group_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        printf("perf_smoke: ERROR - event group setup failed\n");
        return 1;
    }
    for (volatile int i = 0; i < 10000; i++) {}
    if (ioctl(group_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        printf("perf_smoke: ERROR - event group disable failed\n");
        return 1;
    }
    uint64_t group_stat[7] = {0};
    if (read(group_fd, group_stat, sizeof(group_stat)) != sizeof(group_stat) ||
        group_stat[0] != 2 || group_stat[4] == 0 || group_stat[6] == 0 ||
        group_stat[4] == group_stat[6]) {
        printf("perf_smoke: ERROR - invalid group record\n");
        return 1;
    }
    close(member_fd);
    close(group_fd);

    // Match the upstream perf process model: parent owns a disabled event
    // targeting a child, and the child's successful exec enables it.
    int exec_pipe[2];
    if (pipe(exec_pipe) != 0) {
        printf("perf_smoke: ERROR - exec test pipe failed\n");
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        char byte;
        close(exec_pipe[1]);
        if (read(exec_pipe[0], &byte, 1) != 1)
            _exit(2);
        execl("/bin/hello_musl", "hello_musl", NULL);
        _exit(3);
    }
    close(exec_pipe[0]);
    struct perf_event_attr exec_attr = group_attr;
    exec_attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                            PERF_FORMAT_TOTAL_TIME_RUNNING |
                            PERF_FORMAT_ID;
    exec_attr.flags = 1 | (1ULL << 12); // disabled | enable_on_exec
    long exec_fd = perf_event_open(&exec_attr, child, -1, -1, 0);
    uint64_t exec_before[4] = {~0ULL, ~0ULL, ~0ULL, ~0ULL};
    if (exec_fd < 0 || read(exec_fd, exec_before, sizeof(exec_before)) !=
                         sizeof(exec_before) ||
        exec_before[0] != 0 || exec_before[1] != 0) {
        printf("perf_smoke: ERROR - enable_on_exec started early\n");
        return 1;
    }
    if (write(exec_pipe[1], "x", 1) != 1 || waitpid(child, NULL, 0) != child) {
        printf("perf_smoke: ERROR - exec child failed\n");
        return 1;
    }
    uint64_t exec_after[4] = {0};
    if (read(exec_fd, exec_after, sizeof(exec_after)) != sizeof(exec_after) ||
        exec_after[0] == 0 || exec_after[1] == 0) {
        printf("perf_smoke: ERROR - enable_on_exec did not start\n");
        return 1;
    }
    close(exec_pipe[1]);
    close(exec_fd);

    // Test custom software syscall counter
    struct perf_event_attr sw_attr;
    memset(&sw_attr, 0, sizeof(sw_attr));
    sw_attr.type = 1; // PERF_TYPE_SOFTWARE
    sw_attr.size = sizeof(sw_attr);
    sw_attr.config = 12; // PERF_COUNT_SW_SYSCALLS (custom)

    long fd_sw = perf_event_open(&sw_attr, 0, -1, -1, 0);
    if (fd_sw < 0) {
        printf("perf_smoke: ERROR - perf_event_open (software) failed with %ld\n", fd_sw);
        return 1;
    }

    uint64_t s1;
    if (read(fd_sw, &s1, sizeof(s1)) < 8) {
        printf("perf_smoke: ERROR - software read failed\n");
        close(fd_sw);
        return 1;
    }

    // Trigger exactly 5 syscalls
    for (int i = 0; i < 5; i++) {
        getppid();
    }

    uint64_t s2;
    if (read(fd_sw, &s2, sizeof(s2)) < 8) {
        printf("perf_smoke: ERROR - software read failed\n");
        close(fd_sw);
        return 1;
    }

    if (s2 <= s1) {
        printf("perf_smoke: ERROR - syscall counter did not increment: %llu -> %llu\n",
               (unsigned long long)s1, (unsigned long long)s2);
        close(fd_sw);
        return 1;
    }

    printf("perf_smoke: OK - syscalls delta %llu\n", (unsigned long long)(s2 - s1));
    printf("perf_smoke: OK\n");
    close(fd_sw);
    return 0;
}
