// Direct-syscall hello-world for the NARF linux-compat demo.
//
// No libc. No PT_INTERP. No PT_TLS. The kernel's ELF loader stages a
// synthetic TLS region (`userspace/src/process.rs`) and SysV-shaped
// stack (argc=0, argv=NULL, envp=NULL, auxv=AT_NULL) so this entry
// point sees a quiet world.
//
// Syscall numbers are the Linux x86_64 ABI per
// `arch/x86/entry/syscalls/syscall_64.tbl` — exactly what NARF's
// linux-compat surface translates. The whole binary exists to prove
// NARF correctly speaks that ABI for a binary built with stock
// binutils, not against narf-libc.
//
// Rebuild via REGEN.sh in this directory.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    # write(1, msg, 6)
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rip + msg]
    mov     rdx, 6
    syscall

    # exit(0) — Linux SYS_exit = 60. NARF's `Syscall::ExitTask`
    # maps to 60 (userspace/src/syscall.rs:1535). exit_group (231)
    # is not yet in the linux-compat table; using exit avoids a
    # spurious ENOSYS + ud2 trap before the parent reaps.
    mov     rax, 60
    xor     rdi, rdi
    syscall

    # Unreachable; trap just in case.
    ud2

    .section .rodata
msg:
    .ascii "hello\n"
