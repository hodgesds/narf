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
        if (munmap(hp, 2 * 1024 * 1024) != 0) {
            w("numa-fail: hugetlb-munmap\n");
            return 1;
        }
    }

    w("numa-ok\n");
    return 0;
}
