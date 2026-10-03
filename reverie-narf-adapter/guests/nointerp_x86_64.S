// No-interpreter guest: a static ELF whose PT_INTERP names a file no test
// mounts, so an execve of it fails with ENOENT before the image replaces the
// caller's (the failed-exec test's target, guests/execfail_x86_64.S). Started
// anyway, it exits 4.

    .intel_syntax noprefix
    .global _start
    .section .interp, "a"
    .asciz  "/rn-exec/no-such-interp"

    .section .text

_start:
    mov     eax, 60             # exit(4)
    mov     edi, 4
    syscall
    ud2
