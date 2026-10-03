// Probe guest: exits 0 only if gettid() is a real thread ID (positive) and
// getpid() - gettid() == 5, the bias the Probe Tool adds to every getpid it
// handles. Run without that Tool it exits 112. The positivity check means a
// backend that returned the same wrong value (say 0) for both syscalls still
// fails: the difference alone would survive it.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    mov     eax, 39             # getpid
    syscall
    mov     rbx, rax
    mov     eax, 186            # gettid
    syscall
    test    rax, rax
    jle     failed
    sub     rbx, rax
    cmp     rbx, 5
    jne     failed

    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall

failed:
    mov     eax, 60             # exit(112)
    mov     edi, 112
    syscall
    ud2
