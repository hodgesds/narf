// vDSO smoke: prove the kernel maps a real linux-vdso.so.1 and its
// fast-path clock works. Read AT_SYSINFO_EHDR, parse the vDSO ELF to
// resolve __vdso_clock_gettime, call it, and confirm it (a) returns a
// plausible non-zero monotonic time, (b) agrees with the clock_gettime
// syscall within a wide tolerance, (c) advances, and (d) serves
// CLOCK_REALTIME too. Success token "vdso-ok".
//
// Build: see REGEN_vdso_smoke.sh (musl-gcc, static-PIE).
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/auxv.h>
#include <elf.h>

static void w(const char *m) { write(1, m, strlen(m)); }

typedef int (*clock_gettime_fn)(int, struct timespec *);

// Minimal vDSO symbol resolver: walk PT_DYNAMIC for STRTAB/SYMTAB/HASH and
// linear-scan the dynamic symbols (the SysV hash header gives the count).
static void *vdso_sym(uintptr_t base, const char *want) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
    Elf64_Phdr *ph = (Elf64_Phdr *)(base + eh->e_phoff);
    Elf64_Dyn *dyn = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;
    const char *strtab = 0;
    Elf64_Sym *symtab = 0;
    uint32_t *hash = 0;
    for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_STRTAB) strtab = (const char *)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym *)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_HASH) hash = (uint32_t *)(base + d->d_un.d_ptr);
    }
    if (!strtab || !symtab || !hash) return 0;
    uint32_t nchain = hash[1]; // number of dynamic symbols
    for (uint32_t i = 0; i < nchain; i++) {
        if (symtab[i].st_name && strcmp(strtab + symtab[i].st_name, want) == 0)
            return (void *)(base + symtab[i].st_value);
    }
    return 0;
}

static long long ns_of(const struct timespec *t) {
    return (long long)t->tv_sec * 1000000000LL + t->tv_nsec;
}

int main(void) {
    unsigned long base = getauxval(AT_SYSINFO_EHDR);
    if (!base) { w("vdso-fail: no-ehdr\n"); return 1; }

    clock_gettime_fn vgettime = (clock_gettime_fn)vdso_sym(base, "__vdso_clock_gettime");
    if (!vgettime) { w("vdso-fail: no-sym\n"); return 1; }

    // vDSO MONOTONIC must be non-zero and close to the syscall's value.
    struct timespec v, s;
    if (vgettime(CLOCK_MONOTONIC, &v) != 0) { w("vdso-fail: vcall\n"); return 1; }
    if (clock_gettime(CLOCK_MONOTONIC, &s) != 0) { w("vdso-fail: syscall\n"); return 1; }
    long long nv = ns_of(&v), ns = ns_of(&s);
    if (nv <= 0) { w("vdso-fail: zero\n"); return 1; }
    long long d = ns - nv;
    if (d < 0) d = -d;
    if (d > 200000000LL) { w("vdso-fail: skew\n"); return 1; } // within 200ms

    // It must advance.
    struct timespec v2;
    if (vgettime(CLOCK_MONOTONIC, &v2) != 0) { w("vdso-fail: vcall2\n"); return 1; }
    if (ns_of(&v2) < nv) { w("vdso-fail: nonmono\n"); return 1; }

    // CLOCK_REALTIME fast path works too.
    struct timespec r;
    if (vgettime(CLOCK_REALTIME, &r) != 0 || ns_of(&r) <= 0) { w("vdso-fail: rt\n"); return 1; }

    w("vdso-ok\n");
    return 0;
}
