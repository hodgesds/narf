// procfs breadth smoke: /proc/stat — the system-wide kernel/scheduler
// stats top, uptime and vmstat parse. Confirms the cpu / btime / processes
// / procs_running lines are present and well-formed. Success token
// "procfs2-ok".
//
// (Fuller /proc/<pid>/status fields are also added in this change, but the
// per-pid /proc read path has a separate liveness gap — task_info() returns
// None for the running reader — so they aren't exercised here.)
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
    w("procfs2-ok\n");
    return 0;
}
