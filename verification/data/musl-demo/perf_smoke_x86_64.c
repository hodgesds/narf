#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

#define PERF_TYPE_HARDWARE 0
#define PERF_COUNT_HW_CPU_CYCLES 0

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

    long fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("perf_smoke: ERROR - perf_event_open failed with %ld\n", fd);
        return 1;
    }

    uint64_t val1;
    if (read(fd, &val1, sizeof(val1)) < 8) {
        printf("perf_smoke: ERROR - read failed\n");
        return 1;
    }

    // Do some arbitrary loop to consume cycles
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++) {
        dummy += i;
    }

    uint64_t val2;
    if (read(fd, &val2, sizeof(val2)) < 8) {
        printf("perf_smoke: ERROR - read failed\n");
        return 1;
    }

    if (val2 >= val1) {
        printf("perf_smoke: OK - cycles delta %llu\n", (unsigned long long)(val2 - val1));
    } else {
        printf("perf_smoke: ERROR - cycle counter went backwards: %llu -> %llu\n",
               (unsigned long long)val1, (unsigned long long)val2);
        return 1;
    }

    close(fd);
    return 0;
}
