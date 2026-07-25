// NUMA sysfs smoke: confirms /sys/devices/system/node exposes the
// per-node topology userspace tools (numactl/libnuma) read. Checks:
//   - /sys/devices/system/node/online        — "0-1" (two nodes)
//   - /sys/devices/system/node/node0/distance — starts "10 20" (SLIT
//     local=10, remote=20; matches the QEMU -numa dist host config)
//   - /sys/devices/system/node/node1/distance — starts "20 10"
//   - /sys/devices/system/node/node0/meminfo  — has "MemTotal"
// Success token "numa-ok".
//
// Pseudo-files are read with plain open/read.
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sched.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)

static void w(const char *m) { write(1, m, strlen(m)); }

static int slurp(const char *path, char *buf, int cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int total = 0, n;
    while (total < cap - 1 && (n = read(fd, buf + total, cap - 1 - total)) > 0) total += n;
    close(fd);
    buf[total > 0 ? total : 0] = 0;
    return total;
}

// True iff `hay` begins with `pfx` (ignoring nothing; exact prefix).
static int starts(const char *hay, const char *pfx) {
    return strncmp(hay, pfx, strlen(pfx)) == 0;
}

static int has(const char *hay, const char *needle) { return strstr(hay, needle) != 0; }

static int put(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int len = strlen(value);
    int n = write(fd, value, len);
    close(fd);
    return n == len ? 0 : -1;
}

int main(void) {
    char buf[1024];

    // online: two NUMA nodes → "0-1".
    if (slurp("/sys/devices/system/node/online", buf, sizeof buf) <= 0) {
        w("numa-fail: online-open\n");
        return 1;
    }
    if (!starts(buf, "0-1")) { w("numa-fail: online-range\n"); return 1; }

    // node0 distance row: local=10, remote=20.
    if (slurp("/sys/devices/system/node/node0/distance", buf, sizeof buf) <= 0) {
        w("numa-fail: n0-distance-open\n");
        return 1;
    }
    if (!starts(buf, "10 20")) { w("numa-fail: n0-distance\n"); return 1; }

    // node1 distance row: remote=20, local=10.
    if (slurp("/sys/devices/system/node/node1/distance", buf, sizeof buf) <= 0) {
        w("numa-fail: n1-distance-open\n");
        return 1;
    }
    if (!starts(buf, "20 10")) { w("numa-fail: n1-distance\n"); return 1; }

    // node0 meminfo: ps/numastat fields.
    if (slurp("/sys/devices/system/node/node0/meminfo", buf, sizeof buf) <= 0) {
        w("numa-fail: n0-meminfo-open\n");
        return 1;
    }
    if (!has(buf, "MemTotal")) { w("numa-fail: n0-meminfo\n"); return 1; }
    if (!has(buf, "MemFree")) { w("numa-fail: n0-memfree\n"); return 1; }

    // Linux UAPI bits 15/14 must be recognized, and PREFERRED_MANY must
    // steer a fresh page to the sole preferred node.
    unsigned long node1 = 2;
    if (syscall(SYS_set_mempolicy, 0x8000 | 5, &node1, 64) != 0) {
        w("numa-fail: preferred-many-set\n");
        return 1;
    }
    unsigned char *preferred = mmap(0, 4096, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (preferred == MAP_FAILED) {
        w("numa-fail: preferred-many-mmap\n");
        return 1;
    }
    preferred[0] = 0x6e;
    void *preferred_pages[1] = { preferred };
    int preferred_status[1] = { -1 };
    if (syscall(SYS_move_pages, 0, 1, preferred_pages, 0,
                preferred_status, 0) != 0 || preferred_status[0] != 1) {
        w("numa-fail: preferred-many-placement\n");
        return 1;
    }
    if (syscall(SYS_set_mempolicy, 0, 0, 0) != 0) {
        w("numa-fail: preferred-many-reset\n");
        return 1;
    }
    munmap(preferred, 4096);

    // Manual weighted interleave must produce the configured 1:3 cycle.
    if (put("/sys/kernel/mm/mempolicy/weighted_interleave/node0", "1\n") ||
        put("/sys/kernel/mm/mempolicy/weighted_interleave/node1", "3\n")) {
        w("numa-fail: weighted-sysfs\n");
        return 1;
    }
    if (slurp("/sys/kernel/mm/mempolicy/weighted_interleave/auto",
              buf, sizeof buf) <= 0 || !starts(buf, "false")) {
        w("numa-fail: weighted-manual-mode\n");
        return 1;
    }
    unsigned long both_nodes = 3;
    if (syscall(SYS_set_mempolicy, 6, &both_nodes, 64) != 0) {
        w("numa-fail: weighted-set\n");
        return 1;
    }
    unsigned char *weighted = mmap(0, 4 * 4096, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (weighted == MAP_FAILED) {
        w("numa-fail: weighted-mmap\n");
        return 1;
    }
    void *weighted_pages[4];
    int weighted_status[4] = { -1, -1, -1, -1 };
    for (int i = 0; i < 4; i++) {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CPU_SET((i & 1) ? 8 : 0, &affinity);
        if (sched_setaffinity(0, sizeof affinity, &affinity) != 0) {
            w("numa-fail: weighted-affinity\n");
            return 1;
        }
        weighted_pages[i] = weighted + i * 4096;
        weighted[i * 4096] = (unsigned char)i;
    }
    if (syscall(SYS_move_pages, 0, 4, weighted_pages, 0,
                weighted_status, 0) != 0 ||
        weighted_status[0] != 0 || weighted_status[1] != 1 ||
        weighted_status[2] != 1 || weighted_status[3] != 1) {
        w("numa-fail: weighted-placement\n");
        return 1;
    }
    syscall(SYS_set_mempolicy, 0, 0, 0);
    munmap(weighted, 4 * 4096);
    cpu_set_t all_cpus;
    CPU_ZERO(&all_cpus);
    for (int cpu = 0; cpu < 16; cpu++) CPU_SET(cpu, &all_cpus);
    sched_setaffinity(0, sizeof all_cpus, &all_cpus);

    // MPOL_F_NUMA_BALANCING: fault on node 0, run the task on node 1, and
    // keep touching the page until the periodic hint fault migrates it.
    cpu_set_t cpu0;
    CPU_ZERO(&cpu0);
    CPU_SET(0, &cpu0);
    unsigned long node0 = 1;
    if (sched_setaffinity(0, sizeof cpu0, &cpu0) != 0 ||
        syscall(SYS_set_mempolicy, 2, &node0, 64) != 0) {
        w("numa-fail: balancing-set\n");
        return 1;
    }
    volatile unsigned char *balanced =
        mmap(0, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (balanced == MAP_FAILED) {
        w("numa-fail: balancing-mmap\n");
        return 1;
    }
    balanced[0] = 0x41;
    syscall(SYS_set_mempolicy, 0, 0, 0);
    if (syscall(SYS_mbind, (void *)balanced, 4096, (1 << 13) | 2,
                &both_nodes, 64, 0) != 0) {
        w("numa-fail: balancing-mbind\n");
        return 1;
    }
    cpu_set_t cpu8;
    CPU_ZERO(&cpu8);
    CPU_SET(8, &cpu8);
    if (sched_setaffinity(0, sizeof cpu8, &cpu8) != 0) {
        w("numa-fail: balancing-affinity\n");
        return 1;
    }
    void *balanced_pages[1] = { (void *)balanced };
    int balanced_status[1] = { -1 };
    for (unsigned long i = 0; i < 50000000UL; i++) {
        balanced[0] ^= (unsigned char)i;
        if ((i & 0x3ffff) == 0 &&
            syscall(SYS_move_pages, 0, 1, balanced_pages, 0,
                    balanced_status, 0) == 0 &&
            balanced_status[0] == 1)
            break;
    }
    if (balanced_status[0] != 1) {
        w("numa-fail: balancing-migration\n");
        return 1;
    }
    syscall(SYS_set_mempolicy, 0, 0, 0);
    munmap((void *)balanced, 4096);
    sched_setaffinity(0, sizeof all_cpus, &all_cpus);

    // QEMU publishes equal local HMAT bandwidth for both nodes. Re-enabling
    // auto mode must reduce those coordinates back to a 1:1 ratio.
    if (put("/sys/kernel/mm/mempolicy/weighted_interleave/auto", "true\n") ||
        slurp("/sys/kernel/mm/mempolicy/weighted_interleave/node0",
              buf, sizeof buf) <= 0 || !starts(buf, "1") ||
        slurp("/sys/kernel/mm/mempolicy/weighted_interleave/node1",
              buf, sizeof buf) <= 0 || !starts(buf, "1")) {
        w("numa-fail: weighted-auto\n");
        return 1;
    }

    // Real hugetlb mapping smoke. The ordinary suite boots without a
    // reservation and therefore legitimately gets ENOMEM; the dedicated
    // NUMA run supplies `hugepages_2m=2` and exercises the hardware leaf.
    unsigned char *hp = mmap(0, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
                             MAP_HUGE_2MB, -1, 0);
    if (hp == MAP_FAILED) {
        if (errno != ENOMEM) {
            w("numa-fail: hugetlb-mmap\n");
            return 1;
        }
    } else {
        hp[0] = 0x5a;
        hp[2 * 1024 * 1024 - 1] = 0xa5;
        if (hp[0] != 0x5a || hp[2 * 1024 * 1024 - 1] != 0xa5) {
            w("numa-fail: hugetlb-rw\n");
            return 1;
        }
        void *pages[1] = { hp };
        int status[1] = { -1 };
        if (syscall(SYS_move_pages, 0, 1, pages, 0, status, 0) != 0 ||
            status[0] < 0) {
            w("numa-fail: hugetlb-placement\n");
            return 1;
        }
        char maps[8192];
        if (slurp("/proc/self/numa_maps", maps, sizeof maps) <= 0 ||
            !has(maps, "kernelpagesize_kB=2048")) {
            w("numa-fail: hugetlb-numa-maps\n");
            return 1;
        }
        if (munmap(hp, 2 * 1024 * 1024) != 0) {
            w("numa-fail: hugetlb-munmap\n");
            return 1;
        }
    }

    w("numa-ok\n");
    return 0;
}
