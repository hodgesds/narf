#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <string.h>

#define PERF_TYPE_HARDWARE 0
#define PERF_COUNT_HW_CPU_CYCLES 0
#define PERF_FORMAT_TOTAL_TIME_ENABLED (1ULL << 0)
#define PERF_FORMAT_TOTAL_TIME_RUNNING (1ULL << 1)
#define PERF_FORMAT_ID (1ULL << 2)
#define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO('$', 1)
#define PERF_EVENT_IOC_RESET _IO('$', 3)
#define PERF_EVENT_IOC_ID _IOR('$', 7, uint64_t *)

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
