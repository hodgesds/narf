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
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdlib.h>

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

// /proc/self/status SigCgt / SigIgn: bit N-1 is signal N (fs/proc/array.c
// render_sigset_t). systemd reads SigCgt to confirm a Type=notify-reload
// service catches its reload signal (SIGHUP) before accepting READY=1.
static void on_sig(int sig) { (void)sig; }

static unsigned long long status_mask(const char *status, const char *field) {
    const char *p = strstr(status, field);
    return p ? strtoull(p + strlen(field), NULL, 16) : ~0ULL;
}

static int check_sig_masks(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    if (sigaction(SIGHUP, &sa, NULL) != 0 || sigaction(SIGRTMAX, &sa, NULL) != 0) {
        w("procfs2-fail: sigmask: sigaction\n");
        return 1;
    }
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) != 0) { w("procfs2-fail: sigmask: ignore\n"); return 1; }
    static char st[8192];
    if (slurp("/proc/self/status", st, sizeof st) <= 0) { w("procfs2-fail: sigmask: status\n"); return 1; }
    unsigned long long cgt = status_mask(st, "SigCgt:\t");
    unsigned long long ign = status_mask(st, "SigIgn:\t");
    unsigned long long hup = 1ULL << (SIGHUP - 1), intr = 1ULL << (SIGINT - 1);
    unsigned long long rtmax = 1ULL << (SIGRTMAX - 1), pipe = 1ULL << (SIGPIPE - 1);
    if (!(cgt & hup) || (cgt & intr) || !(cgt & rtmax) || !(ign & pipe) || (ign & (pipe << 1))) {
        char m[128];
        snprintf(m, sizeof m, "procfs2-fail: SigCgt %016llx / SigIgn %016llx misplace signal bits\n", cgt, ign);
        w(m);
        return 1;
    }
    return 0;
}

// Linux keeps argv, environ and the auxiliary vector in the mm, so a forked
// child that has not exec'd reports exactly its parent's /proc/self/cmdline,
// environ and auxv (and comm). Chromium's zygote-forked renderers never
// exec; crashpad reads their auxv for AT_PHDR / AT_BASE.
static const char *const fork_files[] = {"/proc/self/auxv", "/proc/self/environ",
                                         "/proc/self/cmdline", "/proc/self/comm"};
#define NFORK_FILES (sizeof fork_files / sizeof fork_files[0])
static char parent_view[NFORK_FILES][4096];
static int parent_len[NFORK_FILES];

// Child side: exit 0 when every file matches the parent's bytes, else the
// 1-based index of the first mismatch.
static int child_compares(void) {
    static char mine[4096];
    for (unsigned i = 0; i < NFORK_FILES; i++) {
        int n = slurp(fork_files[i], mine, sizeof mine);
        if (n != parent_len[i] || memcmp(mine, parent_view[i], (size_t)n) != 0) return (int)i + 1;
    }
    return 0;
}

static int check_fork_identity(const char *how, pid_t pid) {
    int status = 0;
    if (pid < 0) { w("procfs2-fail: fork-identity: fork\n"); return 1; }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        char m[96];
        int idx = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        snprintf(m, sizeof m, "procfs2-fail: %s child sees a different %s\n", how,
                 idx >= 1 && idx <= (int)NFORK_FILES ? fork_files[idx - 1] : "?");
        w(m);
        return 1;
    }
    return 0;
}

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

    if (check_sig_masks()) return 1;
    for (unsigned i = 0; i < NFORK_FILES; i++) {
        parent_len[i] = slurp(fork_files[i], parent_view[i], sizeof parent_view[i]);
        // environ may be empty (the boot shell runs us with no environment);
        // auxv, cmdline and comm never are.
        if (parent_len[i] < 0 || (parent_len[i] == 0 && i != 1)) {
            w("procfs2-fail: fork-identity: parent read\n");
            return 1;
        }
    }
    // fork(2) (musl issues SYS_fork) and clone(SIGCHLD) (glibc's fork) take
    // different kernel paths; both must inherit.
    pid_t pid = fork();
    if (pid == 0) _exit(child_compares());
    if (check_fork_identity("fork", pid)) return 1;
    pid = (pid_t)syscall(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);
    if (pid == 0) _exit(child_compares());
    if (check_fork_identity("clone(SIGCHLD)", pid)) return 1;

    w("procfs2-ok\n");
    return 0;
}
