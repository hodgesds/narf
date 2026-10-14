// Remote process-memory access smoke: PTRACE_PEEK*/POKE*,
// process_vm_readv/process_vm_writev and /proc/<pid>/mem, against a forked
// (copy-on-write) child stopped under PTRACE_TRACEME — exactly the shape
// strace, crashpad and debuggers rely on.
//
// Every expectation is Linux's (kernel/ptrace.c generic_ptrace_peekdata /
// pokedata, mm/process_vm_access.c, fs/proc/base.c mem_*), and the program
// passes on host Linux before it is run on NARF. Success token
// "remotevm-ok"; each failure prints "remotevm-fail: <what>".
//
// Build: see REGEN_remotevm_smoke.sh (musl-gcc, PIE).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile uint64_t global_word = 0x1122334455667788ULL;

static int failures;

static void w(const char *m) { write(1, m, strlen(m)); }

static void fail(const char *what, long got, int err) {
    char b[256];
    snprintf(b, sizeof b, "remotevm-fail: %s (got %#lx errno %d)\n", what, got, err);
    w(b);
    failures++;
}

#define CHECK(cond, what, got, err) do { if (!(cond)) fail(what, (long)(got), err); } while (0)

// Never executed by either process: a POKETEXT target. noinline + used keep
// it a real function body in .text.
__attribute__((noinline, used)) int victim(int x) {
    return x * 7 + 3;
}

// Read a word of code through a volatile pointer: the compiler treats a
// function's bytes as constant and would otherwise reuse an earlier read
// across the tracer's writes.
static uint64_t read_text_word(const void *p) {
    const volatile unsigned char *b = p;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    return v;
}

static pid_t waitpid_nointr(pid_t pid, int *status) {
    pid_t r;
    do {
        r = waitpid(pid, status, 0);
    } while (r < 0 && errno == EINTR);
    return r;
}

// Raw ptrace: the syscall itself, not libc's PEEK convenience.
static long raw_ptrace(long req, pid_t pid, void *addr, void *data) {
    return syscall(SYS_ptrace, req, pid, addr, data);
}

static long peek(pid_t pid, const void *addr, int *err) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    *err = errno;
    return v;
}

int main(void) {
    const long pg = sysconf(_SC_PAGESIZE);

    // Heap word.
    uint64_t *heap = malloc(64);
    heap[0] = 0xa1b2c3d4e5f60718ULL;

    // Two pages with a known word straddling the boundary.
    unsigned char *two = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t straddle = 0x0807060504030201ULL;
    memcpy(two + pg - 4, &straddle, 8);

    // A PROT_NONE page that holds data (FOLL_FORCE must reach it).
    uint64_t *none = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    none[1] = 0x5a5a5a5a12345678ULL;
    mprotect(none, pg, PROT_NONE);

    // A lazy page nobody has touched: reads as zero.
    uint64_t *lazy = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // A private file mapping nobody has faulted.
    char path[] = "/tmp/remotevm-XXXXXX";
    int tfd = mkstemp(path);
    unsigned char fbuf[4096];
    for (int i = 0; i < 4096; i++) fbuf[i] = (unsigned char)(i * 13 + 1);
    if (tfd < 0 || write(tfd, fbuf, sizeof fbuf) != (ssize_t)sizeof fbuf) {
        w("remotevm-fail: temp file setup\n");
        return 1;
    }
    unsigned char *filemap = mmap(0, pg, PROT_READ, MAP_PRIVATE, tfd, 0);
    close(tfd);
    unlink(path);

    // A hole: map two pages, drop the second, so [hole_lo, hole_lo+pg) is
    // mapped and [hole_lo+pg, ...) is not.
    unsigned char *hole_lo = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(hole_lo, 0x77, pg);
    munmap(hole_lo + pg, pg);
    unsigned char *unmapped = hole_lo + pg;

    if (two == MAP_FAILED || none == MAP_FAILED || lazy == MAP_FAILED || filemap == MAP_FAILED ||
        hole_lo == MAP_FAILED) {
        w("remotevm-fail: mmap setup\n");
        return 1;
    }

    uint64_t victim_orig;
    victim_orig = read_text_word((const void *)victim);

    int report[2];
    if (pipe(report) != 0) {
        w("remotevm-fail: pipe\n");
        return 1;
    }

    pid_t c = fork();
    if (c == 0) {
        close(report[0]);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(10);
        raise(SIGSTOP);
        // Resumed: report what the tracer's writes left in OUR memory.
        uint64_t out[4];
        out[0] = global_word;
        out[1] = heap[0];
        out[2] = read_text_word((const void *)victim);
        mprotect(none, pg, PROT_READ);
        out[3] = none[1];
        write(report[1], out, sizeof out);
        _exit(0);
    }
    close(report[1]);

    int st;
    if (waitpid_nointr(c, &st) != c || !WIFSTOPPED(st)) {
        w("remotevm-fail: child did not stop\n");
        return 1;
    }

    int err;
    long v;

    // ── PTRACE_PEEKDATA / PEEKTEXT ──────────────────────────────────
    v = peek(c, (const void *)&global_word, &err);
    CHECK(v == (long)0x1122334455667788ULL && err == 0, "PEEKDATA global", v, err);
    v = peek(c, heap, &err);
    CHECK(v == (long)0xa1b2c3d4e5f60718ULL && err == 0, "PEEKDATA heap", v, err);
    v = peek(c, two + pg - 4, &err);
    CHECK(v == (long)straddle && err == 0, "PEEKDATA across a page boundary", v, err);
    v = peek(c, &none[1], &err);
    CHECK(v == (long)0x5a5a5a5a12345678ULL && err == 0, "PEEKDATA PROT_NONE (FOLL_FORCE)", v, err);
    v = peek(c, lazy, &err);
    CHECK(v == 0 && err == 0, "PEEKDATA untouched lazy page", v, err);
    uint64_t fexp;
    memcpy(&fexp, fbuf + 64, 8);
    v = peek(c, filemap + 64, &err);
    CHECK(v == (long)fexp && err == 0, "PEEKDATA unfaulted private file page", v, err);
    errno = 0;
    v = ptrace(PTRACE_PEEKTEXT, c, (void *)victim, 0);
    CHECK(v == (long)victim_orig && errno == 0, "PEEKTEXT text", v, errno);
    v = peek(c, unmapped, &err);
    CHECK(v == -1 && err == EIO, "PEEKDATA unmapped -> EIO", v, err);
    v = peek(c, hole_lo + pg - 4, &err);
    CHECK(v == -1 && err == EIO, "PEEKDATA word running off the mapping -> EIO", v, err);

    // The raw syscall stores through `data` and returns 0.
    uint64_t out = 0;
    errno = 0;
    v = raw_ptrace(PTRACE_PEEKDATA, c, (void *)&global_word, &out);
    CHECK(v == 0 && out == 0x1122334455667788ULL, "raw PEEKDATA returns 0 and stores *data", v, errno);
    errno = 0;
    v = raw_ptrace(PTRACE_PEEKDATA, c, (void *)&global_word, (void *)8);
    CHECK(v == -1 && errno == EFAULT, "raw PEEKDATA bad data -> EFAULT", v, errno);
    errno = 0;
    v = raw_ptrace(PTRACE_PEEKDATA, c, unmapped, (void *)8);
    CHECK(v == -1 && errno == EIO, "raw PEEKDATA: unmapped (EIO) outranks bad data", v, errno);

    // ── PTRACE_POKEDATA / POKETEXT ──────────────────────────────────
    errno = 0;
    v = ptrace(PTRACE_POKEDATA, c, (void *)&global_word, (void *)0xdeadbeefcafef00dULL);
    CHECK(v == 0, "POKEDATA global", v, errno);
    v = peek(c, (const void *)&global_word, &err);
    CHECK(v == (long)0xdeadbeefcafef00dULL, "POKEDATA global read back", v, err);
    CHECK(global_word == 0x1122334455667788ULL, "POKEDATA leaked into the parent (COW)", global_word, 0);

    uint64_t bp = 0xccccccccccccccccULL;
    errno = 0;
    v = ptrace(PTRACE_POKETEXT, c, (void *)victim, (void *)bp);
    CHECK(v == 0, "POKETEXT read-only text (FOLL_FORCE)", v, errno);
    errno = 0;
    v = ptrace(PTRACE_PEEKTEXT, c, (void *)victim, 0);
    CHECK(v == (long)bp, "POKETEXT read back", v, errno);
    uint64_t victim_now;
    victim_now = read_text_word((const void *)victim);
    CHECK(victim_now == victim_orig, "POKETEXT leaked into the parent's text (COW)", victim_now, 0);

    errno = 0;
    v = ptrace(PTRACE_POKEDATA, c, (void *)&none[1], (void *)0x0102030405060708ULL);
    CHECK(v == 0, "POKEDATA PROT_NONE (FOLL_FORCE)", v, errno);
    v = peek(c, &none[1], &err);
    CHECK(v == 0x0102030405060708L, "POKEDATA PROT_NONE read back", v, err);

    errno = 0;
    v = ptrace(PTRACE_POKEDATA, c, unmapped, (void *)1);
    CHECK(v == -1 && errno == EIO, "POKEDATA unmapped -> EIO", v, errno);

    // ── process_vm_readv / process_vm_writev ────────────────────────
    {
        // Multi-iovec gather/scatter: remote {global, heap} into local {4, 12}.
        unsigned char a[4], b[12];
        struct iovec l[2] = {{a, sizeof a}, {b, sizeof b}};
        struct iovec r[2] = {{(void *)&global_word, 8}, {heap, 8}};
        ssize_t n = process_vm_readv(c, l, 2, r, 2, 0);
        uint64_t g, h, gexp = 0xdeadbeefcafef00dULL, hexp = 0xa1b2c3d4e5f60718ULL;
        memcpy(&g, a, 4);
        memcpy((unsigned char *)&g + 4, b, 4);
        memcpy(&h, b + 4, 8);
        CHECK(n == 16 && g == gexp && h == hexp, "process_vm_readv multi-iovec", n, errno);
    }
    {
        // Partial: 8 mapped bytes, then the hole.
        unsigned char buf[16];
        memset(buf, 0, sizeof buf);
        struct iovec l = {buf, 16};
        struct iovec r = {hole_lo + pg - 8, 16};
        ssize_t n = process_vm_readv(c, &l, 1, &r, 1, 0);
        CHECK(n == 8 && buf[0] == 0x77 && buf[7] == 0x77, "process_vm_readv partial transfer", n, errno);
        // Second remote segment unmapped: the first still counts.
        uint64_t x[2] = {0, 0};
        struct iovec l2 = {x, 16};
        struct iovec r2[2] = {{heap, 8}, {unmapped, 8}};
        n = process_vm_readv(c, &l2, 1, r2, 2, 0);
        CHECK(n == 8 && x[0] == 0xa1b2c3d4e5f60718ULL, "process_vm_readv stops at a faulting segment", n, errno);
        // Nothing transferred: EFAULT.
        errno = 0;
        struct iovec r3 = {unmapped, 8};
        n = process_vm_readv(c, &l2, 1, &r3, 1, 0);
        CHECK(n == -1 && errno == EFAULT, "process_vm_readv unmapped -> EFAULT", n, errno);
        // No FOLL_FORCE: a PROT_NONE page is EFAULT.
        errno = 0;
        struct iovec r4 = {&none[1], 8};
        n = process_vm_readv(c, &l2, 1, &r4, 1, 0);
        CHECK(n == -1 && errno == EFAULT, "process_vm_readv PROT_NONE -> EFAULT", n, errno);
        // Untouched lazy page and unfaulted file page fault in.
        struct iovec r5[2] = {{lazy, 8}, {filemap + 64, 8}};
        x[0] = 1;
        n = process_vm_readv(c, &l2, 1, r5, 2, 0);
        CHECK(n == 16 && x[0] == 0 && x[1] == fexp, "process_vm_readv lazy + file pages", n, errno);
        // Local fault after the first local segment: the prefix counts.
        uint64_t y = 0;
        struct iovec l6[2] = {{&y, 8}, {(void *)unmapped, 8}};
        struct iovec r6 = {heap, 16};
        n = process_vm_readv(c, l6, 2, &r6, 1, 0);
        CHECK(n == 8 && y == 0xa1b2c3d4e5f60718ULL, "process_vm_readv local fault keeps prefix", n, errno);
    }
    {
        uint64_t val = 0x1111222233334444ULL;
        struct iovec l = {&val, 8};
        struct iovec r = {heap, 8};
        ssize_t n = process_vm_writev(c, &l, 1, &r, 1, 0);
        CHECK(n == 8, "process_vm_writev heap", n, errno);
        v = peek(c, heap, &err);
        CHECK(v == (long)0x1111222233334444ULL, "process_vm_writev read back", v, err);
        CHECK(heap[0] == 0xa1b2c3d4e5f60718ULL, "process_vm_writev leaked into the parent (COW)", heap[0], 0);
        // No FOLL_FORCE: read-only text is EFAULT.
        errno = 0;
        struct iovec rt = {(void *)victim, 8};
        n = process_vm_writev(c, &l, 1, &rt, 1, 0);
        CHECK(n == -1 && errno == EFAULT, "process_vm_writev read-only text -> EFAULT", n, errno);
    }
    {
        // Argument validation, in Linux's order.
        uint64_t x;
        struct iovec l = {&x, 8};
        struct iovec r = {heap, 8};
        errno = 0;
        ssize_t n = process_vm_readv(c, &l, 1, &r, 1, 1);
        CHECK(n == -1 && errno == EINVAL, "process_vm_readv flags -> EINVAL", n, errno);
        errno = 0;
        n = process_vm_readv(c, &l, 1025, &r, 1, 0);
        CHECK(n == -1 && errno == EINVAL, "process_vm_readv liovcnt > IOV_MAX -> EINVAL", n, errno);
        errno = 0;
        n = process_vm_readv(c, &l, 1, &r, 1025, 0);
        CHECK(n == -1 && errno == EINVAL, "process_vm_readv riovcnt > IOV_MAX -> EINVAL", n, errno);
        errno = 0;
        n = process_vm_readv(c, &l, 1, (struct iovec *)8, 1, 0);
        CHECK(n == -1 && errno == EFAULT, "process_vm_readv bad rvec -> EFAULT", n, errno);
        // An empty local vector returns 0 before the remote one is read.
        errno = 0;
        n = process_vm_readv(c, &l, 0, (struct iovec *)8, 1, 0);
        CHECK(n == 0, "process_vm_readv empty local -> 0", n, errno);
        // A reaped pid: ESRCH.
        pid_t gone = fork();
        if (gone == 0) _exit(0);
        int gst;
        waitpid_nointr(gone, &gst);
        errno = 0;
        n = process_vm_readv(gone, &l, 1, &r, 1, 0);
        CHECK(n == -1 && errno == ESRCH, "process_vm_readv reaped pid -> ESRCH", n, errno);
    }

    // ── /proc/<pid>/mem ─────────────────────────────────────────────
    {
        char mp[64];
        snprintf(mp, sizeof mp, "/proc/%d/mem", c);
        int fd = open(mp, O_RDWR);
        CHECK(fd >= 0, "open /proc/<pid>/mem", fd, errno);
        if (fd >= 0) {
            uint64_t x = 0;
            ssize_t n = pread(fd, &x, 8, (off_t)(uintptr_t)&global_word);
            CHECK(n == 8 && x == 0xdeadbeefcafef00dULL, "mem pread global", n, errno);
            n = pread(fd, &x, 8, (off_t)(uintptr_t)&none[1]);
            CHECK(n == 8 && x == 0x0102030405060708ULL, "mem pread PROT_NONE (FOLL_FORCE)", n, errno);
            errno = 0;
            n = pread(fd, &x, 8, (off_t)(uintptr_t)unmapped);
            CHECK(n == -1 && errno == EIO, "mem pread unmapped -> EIO", n, errno);
            unsigned char big[32];
            n = pread(fd, big, 32, (off_t)(uintptr_t)(hole_lo + pg - 8));
            CHECK(n == 8 && big[0] == 0x77, "mem pread short at the end of a mapping", n, errno);
            uint64_t bp2 = 0xcdcdcdcdcdcdcdcdULL;
            n = pwrite(fd, &bp2, 8, (off_t)(uintptr_t)victim);
            CHECK(n == 8, "mem pwrite read-only text (FOLL_FORCE)", n, errno);
            n = pread(fd, &x, 8, (off_t)(uintptr_t)victim);
            CHECK(n == 8 && x == bp2, "mem pwrite text read back", n, errno);
            n = pwrite(fd, &bp, 8, (off_t)(uintptr_t)victim);
            CHECK(n == 8, "mem pwrite text restore breakpoint", n, errno);
            errno = 0;
            n = pwrite(fd, &bp2, 8, (off_t)(uintptr_t)unmapped);
            CHECK(n == -1 && errno == EIO, "mem pwrite unmapped -> EIO", n, errno);
            // mem_lseek.
            off_t o = lseek(fd, (off_t)(uintptr_t)heap, SEEK_SET);
            CHECK(o == (off_t)(uintptr_t)heap, "mem lseek SEEK_SET", o, errno);
            n = read(fd, &x, 8);
            CHECK(n == 8 && x == 0x1111222233334444ULL, "mem read at f_pos", n, errno);
            o = lseek(fd, 0, SEEK_CUR);
            CHECK(o == (off_t)(uintptr_t)heap + 8, "mem read advanced f_pos", o, errno);
            o = lseek(fd, -8, SEEK_CUR);
            CHECK(o == (off_t)(uintptr_t)heap, "mem lseek SEEK_CUR", o, errno);
            errno = 0;
            o = lseek(fd, 0, SEEK_END);
            CHECK(o == -1 && errno == EINVAL, "mem lseek SEEK_END -> EINVAL", o, errno);
            errno = 0;
            n = pread(fd, &x, 8, -1);
            CHECK(n == -1 && errno == EINVAL, "mem pread negative offset -> EINVAL", n, errno);
            close(fd);
        }
        snprintf(mp, sizeof mp, "/proc/%d/task/%d/mem", c, c);
        fd = open(mp, O_RDONLY);
        CHECK(fd >= 0, "open /proc/<pid>/task/<tid>/mem", fd, errno);
        if (fd >= 0) {
            uint64_t x = 0;
            ssize_t n = pread(fd, &x, 8, (off_t)(uintptr_t)heap);
            CHECK(n == 8 && x == 0x1111222233334444ULL, "task mem pread", n, errno);
            close(fd);
        }
        fd = open("/proc/self/mem", O_RDONLY);
        CHECK(fd >= 0, "open /proc/self/mem", fd, errno);
        if (fd >= 0) {
            uint64_t x = 0;
            ssize_t n = pread(fd, &x, 8, (off_t)(uintptr_t)&global_word);
            CHECK(n == 8 && x == 0x1122334455667788ULL, "self mem pread", n, errno);
            close(fd);
        }
    }

    // ── A different, unprivileged uid may not reach a root process ───
    if (geteuid() == 0) {
        pid_t parent = getpid();
        pid_t u = fork();
        if (u == 0) {
            if (setresgid(65534, 65534, 65534) != 0 || setresuid(65534, 65534, 65534) != 0) _exit(20);
            uint64_t x;
            struct iovec l = {&x, 8};
            struct iovec r = {(void *)&global_word, 8};
            errno = 0;
            if (process_vm_readv(parent, &l, 1, &r, 1, 0) != -1 || errno != EPERM) _exit(21);
            char mp[64];
            snprintf(mp, sizeof mp, "/proc/%d/mem", parent);
            errno = 0;
            if (open(mp, O_RDONLY) != -1 || errno != EACCES) _exit(22);
            _exit(0);
        }
        int ust;
        waitpid_nointr(u, &ust);
        CHECK(WIFEXITED(ust) && WEXITSTATUS(ust) == 0, "cross-uid process_vm/mem denial (exit code)",
              WIFEXITED(ust) ? WEXITSTATUS(ust) : -1, 0);
    } else {
        w("remotevm: not root, cross-uid denial skipped\n");
    }

    // ── The child sees the tracer's writes; the parent never did ─────
    ptrace(PTRACE_CONT, c, 0, 0);
    uint64_t rep[4];
    ssize_t got = 0;
    while (got < (ssize_t)sizeof rep) {
        ssize_t n = read(report[0], (char *)rep + got, sizeof rep - got);
        if (n <= 0) break;
        got += n;
    }
    CHECK(got == (ssize_t)sizeof rep, "child report", got, errno);
    if (got == (ssize_t)sizeof rep) {
        CHECK(rep[0] == 0xdeadbeefcafef00dULL, "child sees POKEDATA", rep[0], 0);
        CHECK(rep[1] == 0x1111222233334444ULL, "child sees process_vm_writev", rep[1], 0);
        CHECK(rep[2] == bp, "child sees POKETEXT / mem pwrite", rep[2], 0);
        CHECK(rep[3] == 0x0102030405060708ULL, "child sees PROT_NONE POKEDATA", rep[3], 0);
    }
    waitpid_nointr(c, &st);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child exit", st, 0);

    if (failures == 0) {
        w("remotevm-ok\n");
        return 0;
    }
    return 1;
}
