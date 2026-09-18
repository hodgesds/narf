// User FP/SIMD context-switch regression. Competing processes keep distinct
// x87 and YMM0 values live across a raw sched_yield(2), forcing NARF to save
// and restore the complete XSAVE image across preemption, migration, and peer
// register use. A stale CR0.TS software mirror makes the first VMOVDQU run
// without #NM, leaves the task image marked non-live, and is caught on the
// first yield that resumes after a peer.
//
// Build: see REGEN_fpu_preempt_smoke.sh (musl-gcc, PIE).
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 16
#define ROUNDS 1024

static void w(const char *s) { write(STDOUT_FILENO, s, strlen(s)); }

/*
 * Keep x87 and YMM0 live across the raw fork syscall itself.  A libc fork()
 * call is allowed to clobber caller-saved vector registers, so it cannot test
 * the kernel ABI.  Linux fpu_clone() gives the child the exact live xstate at
 * syscall entry; both parent and child must therefore observe these values.
 */
static int fork_fp_inherit(void) {
    __attribute__((aligned(32))) const uint64_t ymm_in[4] = {
        0x0123456789abcdefULL, 0xfedcba9876543210ULL,
        0x55aa55aa33cc33ccULL, 0xc001d00d5eedfaceULL,
    };
    __attribute__((aligned(32))) uint64_t ymm_out[4] = {0, 0, 0, 0};
    const long double x87_in = 0x1.23456789abcdefp+17L;
    long double x87_out = 0.0L;
    long pid;

    __asm__ volatile(
        "vmovdqu (%[vin]), %%ymm0\n\t"
        "fldt (%[xin])\n\t"
        "syscall\n\t"
        "fstpt (%[xout])\n\t"
        "vmovdqu %%ymm0, (%[vout])\n\t"
        "vzeroupper\n\t"
        : "=a"(pid)
        : "0"((long)SYS_fork), [vin] "r"(ymm_in), [vout] "r"(ymm_out),
          [xin] "r"(&x87_in), [xout] "r"(&x87_out)
        : "rcx", "r11", "ymm0", "st", "memory");

    const int intact = memcmp(ymm_in, ymm_out, sizeof(ymm_in)) == 0 &&
                       x87_in == x87_out;
    if (pid == 0)
        _exit(intact ? 0 : 1);
    if (pid < 0 || !intact)
        return 0;

    int status = 0;
    return waitpid((pid_t)pid, &status, 0) == pid && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

static int fp_round_trip(unsigned worker, unsigned round) {
    __attribute__((aligned(32))) uint64_t ymm_in[4];
    __attribute__((aligned(32))) uint64_t ymm_out[4] = {0, 0, 0, 0};
    long double x87_in = (long double)(worker * 4096u + round) + 0.25L;
    long double x87_out = 0.0L;

    for (unsigned i = 0; i < 4; i++)
        ymm_in[i] = 0x9e3779b97f4a7c15ULL * (worker + 1u) ^
                    0xd1b54a32d192ed03ULL * (round + i + 1u);

    __asm__ volatile(
        "vmovdqu (%[vin]), %%ymm0\n\t"
        "fldt (%[xin])\n\t"
        "mov %[yield_nr], %%eax\n\t"
        "syscall\n\t"
        "fstpt (%[xout])\n\t"
        "vmovdqu %%ymm0, (%[vout])\n\t"
        "vzeroupper\n\t"
        :
        : [vin] "r"(ymm_in), [vout] "r"(ymm_out), [xin] "r"(&x87_in),
          [xout] "r"(&x87_out), [yield_nr] "i"(SYS_sched_yield)
        : "rax", "rcx", "r11", "xmm0", "st", "memory");

    return memcmp(ymm_in, ymm_out, sizeof(ymm_in)) == 0 && x87_in == x87_out;
}

static int run_worker(unsigned worker) {
    for (unsigned round = 0; round < ROUNDS; round++) {
        if (!fp_round_trip(worker, round))
            return 1;
    }
    return 0;
}

int main(void) {
    if (!fork_fp_inherit()) {
        w("fpu-preempt-fail: fork did not inherit x87/YMM state\n");
        return 1;
    }

    pid_t children[WORKERS];
    for (unsigned i = 0; i < WORKERS; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            w("fpu-preempt-fail: fork\n");
            return 1;
        }
        if (pid == 0)
            _exit(run_worker(i + 1u));
        children[i] = pid;
    }

    int failed = run_worker(0);
    for (unsigned i = 0; i < WORKERS; i++) {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            failed = 1;
    }

    if (failed) {
        w("fpu-preempt-fail: x87/YMM state changed across sched_yield\n");
        return 1;
    }
    w("fpu-preempt-ok\n");
    return 0;
}
