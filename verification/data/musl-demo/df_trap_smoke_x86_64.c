// Regression for x86 trap entry inheriting userspace's direction flag.
//
// SYSCALL clears DF through IA32_FMASK, but an interrupt gate does not. A
// task can be interrupted between STD and CLD, so common_trap must clear the
// live kernel DF before Rust or any compiler-generated REP MOVS executes.
// The CPU-pushed user RFLAGS must remain untouched for IRETQ.
//
// Make the failure deterministic with an `int $0x80` uname: the kernel copies
// the utsname out through REP MOVSB. Without the entry CLD that copy runs
// backward into the arena prefix and leaves sysname incomplete. With the fix
// it writes "NARF", returns success, and restores DF=1 to this user context;
// the inline asm then clears DF before returning to C.
//
// `int $0x80` is the i386 system-call ABI for every task (as on Linux): the
// call is i386 newuname (122) with the buffer in ebx, so the arena must sit
// below 4 GiB. This PIE loads far above that, so the arena is a fixed
// mapping at 1 GiB rather than a static.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define ARENA_ADDR ((void *)0x40000000UL)

static void w(const char *s) { write(1, s, strlen(s)); }

int main(void) {
    unsigned char *arena = mmap(ARENA_ADDR, 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (arena != ARENA_ADDR) {
        w("df-trap-fail: no arena below 4 GiB\n");
        return 1;
    }
    struct utsname *u = (struct utsname *)(void *)(arena + 512);
    unsigned long flags;
    long nr;

    memset(arena, 0xA5, 1024);
    // Pin the syscall number (122 = i386 newuname) into rax and the buffer
    // into rbx via INPUT operand constraints, not `register long
    // __asm__("rax")` locals. A local register variable is only guaranteed
    // live in its register across an asm if NOTHING clobbers it in between —
    // and GCC's manual warns specifically that an intervening FUNCTION CALL
    // (here `memset`) may clobber it with no reload. Input constraints ("0"
    // ties 122 to the rax output, "b" forces rbx) make the compiler
    // materialise both registers immediately before the trap, regardless of
    // surrounding calls. The i386 gate changes only rax.
    __asm__ volatile(
        "std\n\t"
        "int $0x80\n\t"
        "pushfq\n\t"
        "popq %[flags]\n\t"
        "cld"
        : "=a"(nr), [flags] "=r"(flags)
        : "0"(122L), "b"(u)
        : "memory", "cc");

    if (nr != 0) {
        w("df-trap-fail: uname\n");
        return 1;
    }
    if ((flags & (1UL << 10)) == 0) {
        w("df-trap-fail: user DF not restored\n");
        return 1;
    }
    if (memcmp(u->sysname, "NARF", 5) != 0) {
        w("df-trap-fail: backward kernel copy\n");
        return 1;
    }
    w("df-trap-ok\n");
    return 0;
}
