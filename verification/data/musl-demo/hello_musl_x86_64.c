/* Real musl-static hello-world for the NARF linux-compat demo.
 *
 * Compiled with `musl-gcc -static -Os`, this binary drags musl's
 * full init path: __libc_start_main → init_tls → __init_libc →
 * libc_start_init → main → exit_group. Along the way musl emits
 * the syscalls a stock musl binary actually hits during startup —
 * set_tid_address, rt_sigaction, prlimit, brk, arch_prctl(ARCH_SET_FS),
 * possibly set_robust_list / rseq depending on musl version, then
 * the program's own write + exit_group.
 *
 * That makes this binary the actual end-to-end test of NARF's
 * linux-compat ABI: a stock Linux toolchain emits something the
 * kernel must accept verbatim. Whatever fails (ENOSYS on a
 * specific syscall, EFAULT on a buffer, wrong errno) shows up
 * immediately when the user types `hello_musl` at the shell
 * prompt.
 *
 * Rebuild via REGEN.sh in this directory (requires `musl-gcc`).
 *
 * Linker scripting: NARF requires the user binary to load at
 * `0x0000_0080_0000_xxxx` (PML4[1]); see init.ld + the comment in
 * hello_static_x86_64.S. musl-gcc + -Ttext-segment achieves the
 * same placement, plus `--defsym=_DYNAMIC=...` to satisfy Scrt1.o's
 * PC32 relocation against `_DYNAMIC` (the symbol is meaningless in
 * a static link but the relocation still has to be encodable).
 *
 * Known constraint at this wave: NARF's `syscall`-instruction
 * dispatch (`frame/src/x86_64/syscall.rs:dispatch_syscall` →
 * `kernel_syscall_entry_plain` → `SyscallTable::dispatch`) reads
 * the `plain` handler slot, but every real syscall (sys_write,
 * sys_execve, ...) is installed as a `raw` handler via
 * `install_raw`. So a `syscall` instruction currently returns
 * `invalid_op` for almost everything — musl's `write()` will
 * silently fail, the binary will continue past it, and the
 * eventual `exit_group` will also no-op. A separate sub-wave
 * converges the two dispatch paths; until then this binary boots
 * but doesn't print.
 */

#include <unistd.h>

int main(void) {
    static const char msg[] = "hello from musl\n";
    /* write() is a musl libc call, NOT a raw syscall — exercises
     * musl's ABI shim through to the kernel. */
    write(1, msg, sizeof(msg) - 1);
    return 0;
}
