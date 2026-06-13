// Process & scheduling smoke: vfork, execveat, rseq, faccessat2,
// fchmodat2. The newer entries have no musl wrappers, so they're issued
// raw. Success token "psched-ok".
//
// Build: see REGEN_psched_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/syscall.h>

// Older musl-tools (CI) predate these syscall numbers in <sys/syscall.h>.
// Pin the x86_64 wire numbers so the smoke builds regardless of header age;
// NARF dispatches on the number, not the libc wrapper.
#ifndef SYS_execveat
#define SYS_execveat 322
#endif
#ifndef SYS_rseq
#define SYS_rseq 334
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

static void w(const char *m) { write(1, m, strlen(m)); }

#define ATFD AT_FDCWD

int main(void) {
    // ── vfork: child _exits, parent reaps the status ──
    pid_t pid = vfork();
    if (pid == 0) {
        _exit(42); // child: only _exit/exec is legal after vfork
    }
    if (pid < 0) { w("psched-fail: vfork\n"); return 1; }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) { w("psched-fail: wait\n"); return 1; }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 42) { w("psched-fail: vfork-status\n"); return 1; }

    // ── execveat: a bad path must fail cleanly (dispatch + reshape) ──
    char *argv[] = { "x", NULL };
    char *envp[] = { NULL };
    long r = syscall(SYS_execveat, (long)ATFD, "/no_such_program_xyz", argv, envp, 0L);
    if (r != -1) { w("psched-fail: execveat\n"); return 1; }

    // ── faccessat2 / fchmodat2 on an existing file ──
    const char *path = "/dev/shm/psched_target";
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) { w("psched-fail: open\n"); return 1; }
    close(fd);
    if (syscall(SYS_faccessat2, (long)ATFD, path, 0L /*F_OK*/, 0L) != 0) {
        w("psched-fail: faccessat2\n"); return 1;
    }
    if (syscall(SYS_fchmodat2, (long)ATFD, path, 0644L, 0L) != 0) {
        w("psched-fail: fchmodat2\n"); return 1;
    }

    // ── rseq: register a restartable-sequence area ──
    struct rseq_area {
        uint32_t cpu_id_start;
        uint32_t cpu_id;
        uint64_t rseq_cs;
        uint32_t flags;
    } __attribute__((aligned(32)));
    static struct rseq_area area;
    if (syscall(SYS_rseq, &area, (long)sizeof area, 0L, 0x53053053L) != 0) {
        w("psched-fail: rseq\n"); return 1;
    }

    w("psched-ok\n");
    return 0;
}
