// procfs breadth smoke: the nodes ps/top/free read. Confirms /proc/stat
// (system-wide cpu / btime / processes lines top + uptime parse) and that
// /proc/self/status carries the memory + thread fields ps/top sort on
// (VmSize, VmRSS, Threads, VmPeak). Success token "procfs2-ok".
//
// Build: see REGEN_procfs2_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

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

static int has(const char *hay, const char *needle) { return strstr(hay, needle) != 0; }

int main(void) {
    char buf[4096];
    if (slurp("/proc/stat", buf, sizeof buf) <= 0) { w("procfs2-fail: stat-open\n"); return 1; }
    if (!has(buf, "cpu ")) { w("procfs2-fail: stat-cpu\n"); return 1; }
    if (!has(buf, "btime ")) { w("procfs2-fail: stat-btime\n"); return 1; }
    if (!has(buf, "processes ")) { w("procfs2-fail: stat-processes\n"); return 1; }
    if (!has(buf, "procs_running ")) { w("procfs2-fail: stat-running\n"); return 1; }

    // /proc/self/status — the ps/top memory + thread fields.
    if (slurp("/proc/self/status", buf, sizeof buf) <= 0) { w("procfs2-fail: status-open\n"); return 1; }
    if (!has(buf, "VmSize:")) { w("procfs2-fail: vmsize\n"); return 1; }
    if (!has(buf, "VmRSS:")) { w("procfs2-fail: vmrss\n"); return 1; }
    if (!has(buf, "Threads:")) { w("procfs2-fail: threads\n"); return 1; }
    if (!has(buf, "VmPeak:")) { w("procfs2-fail: vmpeak\n"); return 1; }

    w("procfs2-ok\n");
    return 0;
}
