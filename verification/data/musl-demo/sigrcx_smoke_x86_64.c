// Regression smoke for the SYSRET rcx/r11 clobber on the syscall-path
// rt_sigreturn. An ASYNCHRONOUS signal (SIGALRM via setitimer) is delivered on
// NARF's timer-IRQ return-to-user while a tight asm loop holds sentinels in
// rcx and r11. The handler returns via musl's rt_sigreturn, which uses the
// `syscall` instruction — so the kernel's syscall exit must preserve rcx/r11.
// The buggy `sysretq` tail clobbered rcx (=RIP) / r11 (=RFLAGS), which is
// exactly how stress-ng --cpu-method matrixprod's loop-bound rcx got replaced
// by a text address (infinite loop → SIGSEGV). The fix diverts sigreturn to a
// full-register iretq exit.
//
// The loop keeps rcx = SENT_RCX and r11 = SENT_R11, spins on `got` (set by the
// handler), and captures both registers AFTER the signal round-trip. If either
// changed, the sigreturn corrupted it. Success token "sigrcx-ok".
//
// Build: see REGEN_sigrcx_smoke.sh (musl-gcc, PIE).
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>

static void w(const char *m) { write(1, m, strlen(m)); }

volatile sig_atomic_t got = 0;
static void handler(int sig) {
    (void)sig;
    got = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = 0; // no SA_RESTART; async delivery on return-to-user
    if (sigaction(SIGALRM, &sa, NULL) != 0) { w("sigrcx-fail: sigaction\n"); return 1; }

    // Fire SIGALRM ~150 ms out — long enough that the asm loop below is
    // already spinning (registers live) when it lands.
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_usec = 150000;
    if (setitimer(ITIMER_REAL, &it, NULL) != 0) { w("sigrcx-fail: setitimer\n"); return 1; }

    const uint64_t SENT_RCX = 0xCAFEBABEDEADBEEFULL; // not a valid RIP
    const uint64_t SENT_R11 = 0x1122334455667788ULL; // not a valid RFLAGS
    uint64_t out_rcx = 0, out_r11 = 0;

    // Hold the sentinels in rcx/r11 and spin until the handler sets `got`.
    // Nothing in the loop body touches rcx/r11 — only an intervening async
    // signal + sigreturn can change them. Capture both once the flag flips.
    __asm__ volatile(
        "mov %[src], %%rcx\n\t"
        "mov %[sr11], %%r11\n\t"
        "1:\n\t"
        "cmpl $0, %[flag]\n\t"
        "je 1b\n\t"
        "mov %%rcx, %[orcx]\n\t"
        "mov %%r11, %[or11]\n\t"
        : [orcx] "=&r"(out_rcx), [or11] "=&r"(out_r11)
        : [src] "r"(SENT_RCX), [sr11] "r"(SENT_R11), [flag] "m"(got)
        : "rcx", "r11", "cc", "memory");

    if (out_rcx == SENT_RCX && out_r11 == SENT_R11) {
        w("sigrcx-ok\n");
        return 0;
    }
    char buf[96];
    int n = snprintf(buf, sizeof(buf),
                     "sigrcx-fail: rcx=%#llx r11=%#llx\n",
                     (unsigned long long)out_rcx, (unsigned long long)out_r11);
    if (n > 0) write(1, buf, (size_t)n);
    return 1;
}
