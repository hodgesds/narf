// NARF vDSO — a real fast-path linux-vdso.so.1.
//
// The kernel maps this PIC shared object plus a read-only "vvar" page into
// every process and points AT_SYSINFO_EHDR at the ELF header here. libc
// (and the NARF vdso smoke) resolve the versioned symbols below and call
// them to read the clock WITHOUT a syscall: each reads the CPU counter
// (rdtsc / cntvct) and converts using the cycles_per_ns + wall_offset the
// kernel publishes in the vvar page — the exact same arithmetic the
// clock_gettime syscall does, so results match bit-for-bit. Unsupported
// clocks fall back to the real syscall.
//
// The vvar page is mapped immediately before this object, so it lives at
// `__ehdr_start - 4096` (a hidden, PC-relative reference — no GOT, no
// runtime relocations).
//
// Built per-arch by verification/build.rs with clang + lld; see
// vdso_x86_64.lds / vdso_aarch64.lds for the layout + version script.

#include <stdint.h>

struct vvar {
    uint32_t seq; // seqlock: odd while the kernel is updating
    uint32_t cycles_per_ns; // == time crate CYCLES_PER_NS (>= 1)
    int64_t wall_offset_ns; // realtime_ns = monotonic_ns + wall_offset_ns
};

struct vdso_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};
struct vdso_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_BOOTTIME 7

#define NS_PER_SEC 1000000000ULL

// The vDSO ELF header address; the vvar page sits one page before it.
extern const char __ehdr_start[] __attribute__((visibility("hidden")));
#define VVAR ((const volatile struct vvar *)(__ehdr_start - 4096))

static inline uint64_t read_cycles(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi)::"memory");
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t v;
    __asm__ __volatile__("isb\n\tmrs %0, cntvct_el0" : "=r"(v)::"memory");
    return v;
#else
    return 0;
#endif
}

// Read a stable (cycles_per_ns, wall_offset) snapshot under the seqlock,
// then convert the current counter to nanoseconds. Returns 0 and stores ns
// for a supported clock; returns -1 for clocks the fast path doesn't cover.
static int vdso_now_ns(int clk, uint64_t *out_ns) {
    const volatile struct vvar *vv = VVAR;
    uint32_t cpns;
    int64_t off;
    for (;;) {
        uint32_t seq = __atomic_load_n(&vv->seq, __ATOMIC_ACQUIRE);
        if (seq & 1u) {
            continue; // update in progress; retry
        }
        cpns = vv->cycles_per_ns;
        off = vv->wall_offset_ns;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (seq == __atomic_load_n(&vv->seq, __ATOMIC_ACQUIRE)) {
            break;
        }
    }
    if (cpns == 0) {
        cpns = 1;
    }
    uint64_t ns = read_cycles() / (uint64_t)cpns;
    switch (clk) {
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_RAW:
    case CLOCK_BOOTTIME:
        break;
    case CLOCK_REALTIME:
        ns += (uint64_t)off;
        break;
    default:
        return -1;
    }
    *out_ns = ns;
    return 0;
}

// ── raw syscall fallback ────────────────────────────────────────────
#if defined(__x86_64__)
#define SYS_clock_gettime 228
#define SYS_gettimeofday 96
#define SYS_clock_getres 229
#define SYS_getcpu 309
#define SYS_time 201
#elif defined(__aarch64__)
#define SYS_clock_gettime 113
#define SYS_gettimeofday 169
#define SYS_clock_getres 114
#define SYS_getcpu 168
#endif

static long vdso_syscall2(long n, long a0, long a1) {
#if defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10");
    (void)r10;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(a0), "S"(a1)
                         : "rcx", "r11", "memory");
    return ret;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
    return x0;
#else
    (void)n;
    (void)a0;
    (void)a1;
    return -38; // -ENOSYS
#endif
}

static int impl_clock_gettime(int clk, struct vdso_timespec *ts) {
    uint64_t ns;
    if (vdso_now_ns(clk, &ns) == 0) {
        ts->tv_sec = (int64_t)(ns / NS_PER_SEC);
        ts->tv_nsec = (int64_t)(ns % NS_PER_SEC);
        return 0;
    }
    return (int)vdso_syscall2(SYS_clock_gettime, clk, (long)ts);
}

static int impl_gettimeofday(struct vdso_timeval *tv, void *tz) {
    uint64_t ns;
    if (tv && tz == 0 && vdso_now_ns(CLOCK_REALTIME, &ns) == 0) {
        tv->tv_sec = (int64_t)(ns / NS_PER_SEC);
        tv->tv_usec = (int64_t)((ns % NS_PER_SEC) / 1000);
        return 0;
    }
    return (int)vdso_syscall2(SYS_gettimeofday, (long)tv, (long)tz);
}

static int impl_clock_getres(int clk, struct vdso_timespec *res) {
    return (int)vdso_syscall2(SYS_clock_getres, clk, (long)res);
}

static int impl_getcpu(unsigned *cpu, unsigned *node) {
    // NARF is single-CPU / single-node; answer directly, no syscall.
    if (cpu) {
        *cpu = 0;
    }
    if (node) {
        *node = 0;
    }
    return 0;
}

// ── exported, arch-named entry points ───────────────────────────────
#if defined(__x86_64__)
int __vdso_clock_gettime(int clk, struct vdso_timespec *ts) {
    return impl_clock_gettime(clk, ts);
}
int __vdso_gettimeofday(struct vdso_timeval *tv, void *tz) {
    return impl_gettimeofday(tv, tz);
}
int __vdso_clock_getres(int clk, struct vdso_timespec *res) {
    return impl_clock_getres(clk, res);
}
long __vdso_getcpu(unsigned *cpu, unsigned *node, void *unused) {
    (void)unused;
    return impl_getcpu(cpu, node);
}
int64_t __vdso_time(int64_t *tp) {
    uint64_t ns;
    if (vdso_now_ns(CLOCK_REALTIME, &ns) == 0) {
        int64_t s = (int64_t)(ns / NS_PER_SEC);
        if (tp) {
            *tp = s;
        }
        return s;
    }
    return vdso_syscall2(SYS_time, (long)tp, 0);
}
#elif defined(__aarch64__)
int __kernel_clock_gettime(int clk, struct vdso_timespec *ts) {
    return impl_clock_gettime(clk, ts);
}
int __kernel_gettimeofday(struct vdso_timeval *tv, void *tz) {
    return impl_gettimeofday(tv, tz);
}
int __kernel_clock_getres(int clk, struct vdso_timespec *res) {
    return impl_clock_getres(clk, res);
}
int __kernel_getcpu(unsigned *cpu, unsigned *node, void *unused) {
    (void)unused;
    return impl_getcpu(cpu, node);
}
#endif
