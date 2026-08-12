// Regression for x86 trap entry inheriting userspace's direction flag.
//
// SYSCALL clears DF through IA32_FMASK, but an interrupt gate does not. A
// task can be interrupted between STD and CLD, so common_trap must clear the
// live kernel DF before Rust or any compiler-generated REP MOVS executes.
// The CPU-pushed user RFLAGS must remain untouched for IRETQ.
//
// Make the failure deterministic with int $0x80 uname(2): the kernel copies
// the utsname out through REP MOVSB. Without the entry CLD that copy runs
// backward into the arena prefix and leaves sysname incomplete. With the fix
// it writes "NARF", returns success, and restores DF=1 to this user context;
// the inline asm then clears DF before returning to C.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static void w(const char *s) { write(1, s, strlen(s)); }

int main(void) {
    static unsigned char arena[1024];
    struct utsname *u = (struct utsname *)(void *)(arena + 512);
    unsigned long flags;
    register long nr __asm__("rax") = 63; // x86_64 Linux uname
    register void *arg __asm__("rdi") = u;

    memset(arena, 0xA5, sizeof(arena));
    __asm__ volatile(
        "std\n\t"
        "int $0x80\n\t"
        "pushfq\n\t"
        "popq %[flags]\n\t"
        "cld"
        : "+a"(nr), "+D"(arg), [flags] "=r"(flags)
        :
        : "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "memory", "cc");

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
