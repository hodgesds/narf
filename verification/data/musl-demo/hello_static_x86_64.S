// Direct-syscall hello-world for the NARF linux-compat demo.
//
// No libc. No PT_INTERP. No PT_TLS. The kernel's ELF loader stages a
// synthetic TLS region (`userspace/src/process.rs`) and SysV-shaped
// stack (argc=0, argv=NULL, envp=NULL, auxv=AT_NULL) so this entry
// point sees a quiet world.
//
// Syscall numbers are the Linux x86_64 ABI per
// `arch/x86/entry/syscalls/syscall_64.tbl` — exactly what NARF's
// linux-compat surface translates.
//
// IMPORTANT — gate selection: NARF uses `int 0x80` as the user
// gate, not the modern `syscall` instruction. `user-runtime/src/
// lib.rs:16` documents the choice; narf-libc's syscall wrappers
// all expand to `int 0x80`. A binary using the raw `syscall`
// instruction either misroutes through an uninitialised
// IA32_LSTAR or returns no-op (the kernel-side handler expects
// the int-0x80 frame layout, not the syscall regs). So this
// binary uses `int 0x80` too — it remains a stock-binutils ELF,
// no narf-libc dependency, but speaks the right kernel gate.
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
    int     0x80

    # exit(0) — Linux SYS_exit = 60. NARF's `Syscall::ExitTask`
    # maps to 60 (userspace/src/syscall.rs:1535). exit_group (231)
    # is not yet in the linux-compat table.
    mov     rax, 60
    xor     rdi, rdi
    int     0x80

    # Unreachable; trap just in case.
    ud2

    .section .rodata
msg:
    .ascii "hello\n"
