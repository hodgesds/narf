// seccomp(2) from ring 3, checked against Linux.
//
// Chromium decides whether it can sandbox with exactly these probes
// (sandbox/linux/seccomp-bpf/sandbox_bpf.cc): prctl(PR_SET_SECCOMP,
// SECCOMP_MODE_FILTER, NULL) and seccomp(SET_MODE_FILTER, TSYNC, NULL) must
// both fail with EFAULT — the kernel looked at the flags and went to read the
// program. NARF answered 0 and enforced nothing, so Chromium logged "Lacking
// support for seccomp-bpf sandbox", and a sandboxed renderer would have had
// no filter at all.
//
// Covered: the EFAULT probes; flag/program validation errnos; the NNP /
// CAP_SYS_ADMIN gate (EACCES); GET_ACTION_AVAIL and GET_NOTIF_SIZES;
// PR_GET_SECCOMP and /proc/self/status; RET_ERRNO (also for an unknown
// syscall number); RET_TRAP with the siginfo Chromium's SIGSYS handler
// insists on (si_code, si_errno, si_syscall, si_arch, si_call_addr == RIP,
// RAX == nr) and a handler-supplied return value; RET_USER_NOTIF and
// RET_TRACE without a listener/tracer (ENOSYS), and a PTRACE_EVENT_SECCOMP
// tracer rewriting the pending syscall through PTRACE_POKEUSER; stacking and
// precedence;
// inheritance by fork and by threads; TSYNC (sync, failure tid,
// TSYNC_ESRCH); RET_KILL_PROCESS, RET_KILL_THREAD; strict mode.
//
// Success token "seccomp-ok".
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <unistd.h>

// <linux/filter.h>, <linux/seccomp.h>, <linux/audit.h> — musl ships none.
struct sock_filter {
    unsigned short code;
    unsigned char jt, jf;
    unsigned k;
};
struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};
struct seccomp_data {
    int nr;
    unsigned arch;
    unsigned long long instruction_pointer;
    unsigned long long args[6];
};
#define BPF_LD 0x00
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JEQ 0x10
#define BPF_K 0x00
#define BPF_STMT(code, k) {(unsigned short)(code), 0, 0, (k)}
#define BPF_JUMP(code, k, jt, jf) {(unsigned short)(code), (jt), (jf), (k)}
#define AUDIT_ARCH_X86_64 0xC000003Eu
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES 3
#define SECCOMP_FILTER_FLAG_TSYNC (1u << 0)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1u << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1u << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1u << 4)
#define SECCOMP_RET_KILL_PROCESS 0x80000000u
#define SECCOMP_RET_KILL_THREAD 0x00000000u
#define SECCOMP_RET_TRAP 0x00030000u
#define SECCOMP_RET_ERRNO 0x00050000u
#define SECCOMP_RET_USER_NOTIF 0x7fc00000u
#define SECCOMP_RET_TRACE 0x7ff00000u
#define SECCOMP_RET_LOG 0x7ffc0000u
#define SECCOMP_RET_ALLOW 0x7fff0000u
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP 0x80
#endif
#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

static int fails;
#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("seccomp-fail: " __VA_ARGS__);                              \
            printf(" (errno=%d)\n", errno);                                    \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static long sc(unsigned op, unsigned flags, void *args) {
    return syscall(SYS_seccomp, op, flags, args);
}

// Return `ret_hit` for syscall `nr`, ALLOW for everything else.
static int install(int nr, unsigned ret_hit, unsigned flags) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, ret_hit),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = {.len = sizeof(f) / sizeof(f[0]), .filter = f};
    return (int)sc(SECCOMP_SET_MODE_FILTER, flags, &p);
}

static int status_field(const char *key) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int v = -1;
    size_t n = strlen(key);
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, key, n) && line[n] == ':') v = atoi(line + n + 1);
    fclose(f);
    return v;
}

static int child_status(pid_t c) {
    int st = 0;
    while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
    return st;
}

// A seccomp TRACE stop is special: Linux lets the tracer replace orig_rax
// before continuing, then rechecks that replacement once and dispatches it.
// Use PEEKUSER/POKEUSER instead of a libc user_regs_struct so this remains a
// standalone musl-demo source. `orig_rax` is word 15 in x86_64's register
// layout (struct user_regs_struct).
static int trace_rewrite_smoke(void) {
    const unsigned long ORIG_RAX = 15 * sizeof(unsigned long);
    pid_t c = fork();
    if (c < 0) return 1;
    if (c == 0) {
        long expected = syscall(SYS_getppid);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(1);
        raise(SIGSTOP);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(2);
        if (install(SYS_getpid, SECCOMP_RET_TRACE | 23, 0) != 0) _exit(3);
        _exit(syscall(SYS_getpid) == expected ? 0 : 4);
    }

    int st;
    if (waitpid(c, &st, 0) != c || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP)
        goto fail;
    if (ptrace(PTRACE_SETOPTIONS, c, 0, (void *)PTRACE_O_TRACESECCOMP) != 0)
        goto fail;
    if (ptrace(PTRACE_CONT, c, 0, 0) != 0) goto fail;
    if (waitpid(c, &st, 0) != c || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP ||
        ((unsigned)st >> 16) != PTRACE_EVENT_SECCOMP)
        goto fail;

    errno = 0;
    if (ptrace(PTRACE_PEEKUSER, c, (void *)ORIG_RAX, 0) != SYS_getpid || errno != 0)
        goto fail;
    if (ptrace(PTRACE_POKEUSER, c, (void *)ORIG_RAX, (void *)SYS_getppid) != 0)
        goto fail;
    if (ptrace(PTRACE_CONT, c, 0, 0) != 0) goto fail;
    if (waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
        return 1;
    return 0;

fail:
    kill(c, SIGKILL);
    while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
    return 1;
}

// ── SIGSYS handler: Chromium's sanity checks, then emulate the call. ──
static volatile int trap_hits;
static volatile int trap_bad;
static void on_sigsys(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    greg_t *g = uc->uc_mcontext.gregs;
    if (sig != SIGSYS || si->si_code != SYS_SECCOMP || si->si_errno != 7 ||
        si->si_syscall != SYS_getppid || si->si_arch != AUDIT_ARCH_X86_64 ||
        (greg_t)si->si_call_addr != g[REG_RIP] || g[REG_RAX] != SYS_getppid)
        trap_bad++;
    trap_hits++;
    g[REG_RAX] = 1234;
}

static volatile int thread_go, thread_done;
static volatile long thread_result;
static void *worker(void *a) {
    (void)a;
    while (!thread_go) usleep(1000);
    thread_result = syscall(SYS_getpid);
    thread_done = 1;
    return 0;
}

static void *own_filter(void *a) {
    (void)a;
    // A filter of this thread's own: not an ancestor of the main thread's.
    install(SYS_getuid, SECCOMP_RET_ERRNO | 3, 0);
    while (!thread_go) usleep(1000);
    return 0;
}

int main(void) {
    // 1. The probes Chromium runs, before any state is changed.
    errno = 0;
    CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0, 0, 0) == -1 && errno == EFAULT,
          "prctl(PR_SET_SECCOMP, FILTER, NULL) not EFAULT");
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, NULL) == -1 && errno == EFAULT,
          "seccomp(FILTER, TSYNC, NULL) not EFAULT");
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_SPEC_ALLOW, NULL) == -1 && errno == EFAULT,
          "seccomp(FILTER, SPEC_ALLOW, NULL) not EFAULT");
    CHECK(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0, "PR_GET_SECCOMP not 0 before");

    // 2. Argument validation, in Linux's order.
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 1u << 6, NULL) == -1 && errno == EINVAL, "unknown flag not EINVAL");
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER,
             SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER, NULL) == -1 &&
              errno == EINVAL,
          "TSYNC|NEW_LISTENER without TSYNC_ESRCH not EINVAL");
    errno = 0;
    CHECK(sc(99, 0, NULL) == -1 && errno == EINVAL, "unknown op not EINVAL");
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_STRICT, 1, NULL) == -1 && errno == EINVAL, "STRICT with flags not EINVAL");
    struct sock_fprog empty = {.len = 0, .filter = NULL};
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 0, &empty) == -1 && errno == EINVAL, "len 0 not EINVAL");

    // 3. Action availability and notification sizes.
    unsigned acts[] = {SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP,
                       SECCOMP_RET_ERRNO, SECCOMP_RET_USER_NOTIF, SECCOMP_RET_TRACE,
                       SECCOMP_RET_LOG, SECCOMP_RET_ALLOW};
    for (unsigned i = 0; i < sizeof acts / sizeof acts[0]; i++)
        CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 0, &acts[i]) == 0, "action %#x not available", acts[i]);
    unsigned bogus = 0x12340000;
    errno = 0;
    CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 0, &bogus) == -1 && errno == EOPNOTSUPP, "bogus action not EOPNOTSUPP");
    errno = 0;
    CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 1, &bogus) == -1 && errno == EINVAL, "ACTION_AVAIL flags not EINVAL");
    unsigned short sizes[3] = {0};
    CHECK(sc(SECCOMP_GET_NOTIF_SIZES, 0, sizes) == 0 && sizes[0] == 80 && sizes[1] == 24 && sizes[2] == 64,
          "notif sizes %u/%u/%u", sizes[0], sizes[1], sizes[2]);

    // 4. Without no_new_privs and without CAP_SYS_ADMIN: EACCES. Drop
    //    privilege in a child when running as root.
    pid_t c = fork();
    if (c == 0) {
        if (geteuid() == 0 && setresuid(65534, 65534, 65534) != 0) _exit(2);
        errno = 0;
        int rc = install(SYS_getpid, SECCOMP_RET_ERRNO | 1, 0);
        _exit(rc == -1 && errno == EACCES ? 0 : 1);
    }
    int st = child_status(c);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "filter without NNP/CAP_SYS_ADMIN not EACCES %#x", st);

    // 5. A bad program: an opcode classic BPF does not have, a misaligned
    //    load, a jump out of range. All EINVAL (NNP set from here on).
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "PR_SET_NO_NEW_PRIVS");
    struct sock_filter badop[] = {{0xffff, 0, 0, 0}, BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_filter misal[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 2), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_filter jump[] = {BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_filter *bad[] = {badop, misal, jump};
    for (int i = 0; i < 3; i++) {
        struct sock_fprog p = {.len = 2, .filter = bad[i]};
        errno = 0;
        CHECK(sc(SECCOMP_SET_MODE_FILTER, 0, &p) == -1 && errno == EINVAL, "bad program %d not EINVAL", i);
    }
    struct sock_fprog nullprog = {.len = 1, .filter = NULL};
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 0, &nullprog) == -1 && errno == EINVAL, "NULL program not EINVAL");
    struct sock_fprog faulty = {.len = 1, .filter = (void *)8};
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 0, &faulty) == -1 && errno == EFAULT, "unreadable program not EFAULT");
    CHECK(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0, "a refused filter changed the mode");

    // 6. ERRNO, status, stacking, an unknown syscall, USER_NOTIF/TRACE.
    c = fork();
    if (c == 0) {
        if (install(SYS_getpid, SECCOMP_RET_ERRNO | 42, 0) != 0) _exit(10);
        errno = 0;
        if (syscall(SYS_getpid) != -1 || errno != 42) _exit(11);
        if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) _exit(12);
        if (status_field("Seccomp") != 2 || status_field("Seccomp_filters") != 1) _exit(13);
        // Unknown syscall 1000: the filter's ERRNO, not ENOSYS.
        if (install(1000, SECCOMP_RET_ERRNO | 77, 0) != 0) _exit(14);
        errno = 0;
        if (syscall(1000) != -1 || errno != 77) _exit(15);
        if (status_field("Seccomp_filters") != 2) _exit(16);
        // The older filter still applies under the newer one.
        errno = 0;
        if (syscall(SYS_getpid) != -1 || errno != 42) _exit(17);
        // Precedence: a newer ERRNO on getpid vs older ERRNO — both ERRNO,
        // first (newest) in walk order wins on equal action.
        if (install(SYS_getpid, SECCOMP_RET_ERRNO | 43, 0) != 0) _exit(18);
        errno = 0;
        if (syscall(SYS_getpid) != -1 || errno != 43) _exit(19);
        // No listener / no tracer: ENOSYS.
        if (install(SYS_getuid, SECCOMP_RET_USER_NOTIF, 0) != 0) _exit(20);
        errno = 0;
        if (syscall(SYS_getuid) != -1 || errno != ENOSYS) _exit(21);
        if (install(SYS_getgid, SECCOMP_RET_TRACE | 5, 0) != 0) _exit(22);
        errno = 0;
        if (syscall(SYS_getgid) != -1 || errno != ENOSYS) _exit(23);
        // A forked grandchild inherits the chain.
        pid_t g = fork();
        if (g == 0) {
            errno = 0;
            _exit(syscall(SYS_getpid) == -1 && errno == 43 ? 0 : 1);
        }
        int gs = child_status(g);
        if (!WIFEXITED(gs) || WEXITSTATUS(gs) != 0) _exit(24);
        // Mode change from FILTER to STRICT is refused.
        errno = 0;
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != -1 || errno != EINVAL) _exit(25);
        _exit(0);
    }
    st = child_status(c);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "ERRNO/stacking child status %#x", st);

    // 7. TRAP: Chromium's SIGSYS contract.
    c = fork();
    if (c == 0) {
        struct sigaction sa = {0};
        sa.sa_sigaction = on_sigsys;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSYS, &sa, 0);
        if (install(SYS_getppid, SECCOMP_RET_TRAP | 7, 0) != 0) _exit(30);
        long r = syscall(SYS_getppid);
        if (trap_hits != 1) _exit(31);
        if (trap_bad) _exit(32);
        if (r != 1234) _exit(33);
        // A blocked SIGSYS cannot dodge the trap: the task dies instead.
        pid_t g = fork();
        if (g == 0) {
            sigset_t s;
            sigemptyset(&s);
            sigaddset(&s, SIGSYS);
            sigprocmask(SIG_BLOCK, &s, 0);
            syscall(SYS_getppid);
            _exit(0);
        }
        int gs = child_status(g);
        if (!WIFSIGNALED(gs) || WTERMSIG(gs) != SIGSYS) _exit(34);
        _exit(0);
    }
    st = child_status(c);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "TRAP child status %#x", st);

    // 8. A seccomp TRACE listener can replace orig_rax. The replacement is
    // rechecked against the filter and is the syscall actually dispatched.
    CHECK(trace_rewrite_smoke() == 0, "seccomp TRACE syscall rewrite");

    // 9. TSYNC: a thread created before the filter is synced to it.
    c = fork();
    if (c == 0) {
        pthread_t t;
        thread_go = 0;
        pthread_create(&t, 0, worker, 0);
        if (install(SYS_getpid, SECCOMP_RET_ERRNO | 9, SECCOMP_FILTER_FLAG_TSYNC) != 0) _exit(41);
        thread_go = 1;
        pthread_join(t, 0);
        _exit(thread_result == -1 ? 0 : 42);
    }
    st = child_status(c);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "TSYNC thread not filtered %#x", st);
    // TSYNC refused: a sibling with a non-ancestral filter.
    c = fork();
    if (c == 0) {
        pthread_t t;
        thread_go = 0;
        pthread_create(&t, 0, own_filter, 0);
        usleep(100000);
        long r = install(SYS_getpid, SECCOMP_RET_ERRNO | 9, SECCOMP_FILTER_FLAG_TSYNC);
        if (r <= 0) _exit(43); // the sibling's tid
        errno = 0;
        r = install(SYS_getpid, SECCOMP_RET_ERRNO | 9,
                    SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH);
        if (r != -1 || errno != ESRCH) _exit(44);
        thread_go = 1;
        pthread_join(t, 0);
        _exit(0);
    }
    st = child_status(c);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "TSYNC refusal child status %#x", st);

    // 10. KILL_PROCESS and KILL_THREAD (last thread): killed by SIGSYS.
    c = fork();
    if (c == 0) {
        install(SYS_getpid, SECCOMP_RET_KILL_PROCESS, 0);
        syscall(SYS_getpid);
        _exit(0);
    }
    st = child_status(c);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS, "KILL_PROCESS status %#x", st);
    c = fork();
    if (c == 0) {
        install(SYS_getpid, SECCOMP_RET_KILL_THREAD, 0);
        syscall(SYS_getpid);
        _exit(0);
    }
    st = child_status(c);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS, "KILL_THREAD status %#x", st);

    // 11. Strict mode: write works, anything else is SIGKILL.
    c = fork();
    if (c == 0) {
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0) _exit(50);
        if (syscall(SYS_write, 1, "", 0) != 0) syscall(SYS_exit, 51);
        syscall(SYS_getpid);
        syscall(SYS_exit, 52);
    }
    st = child_status(c);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "strict status %#x", st);

    if (fails == 0) printf("seccomp-ok\n");
    return fails != 0;
}
