// Signal-hook guest: installs counting handlers for SIGUSR1 and SIGUSR2,
// sends itself SIGUSR1 and then SIGUSR2 with tkill, and exits 0 when the
// SIGUSR1 handler ran once and the SIGUSR2 handler never ran. Each signal is
// pending when its tkill returns, so it is delivered, or not, at that return.
// Exits 70 when the SIGUSR1 handler did not run exactly once, 71 when the
// SIGUSR2 handler ran, and 60..=61 when a setup syscall failed.

    .intel_syntax noprefix
    .global _start

    .equ SYS_RT_SIGACTION, 13
    .equ SYS_RT_SIGRETURN, 15
    .equ SYS_EXIT, 60
    .equ SYS_GETTID, 186
    .equ SYS_TKILL, 200
    .equ SIGUSR1, 10
    .equ SIGUSR2, 12
    .equ SA_RESTORER, 0x04000000

    .section .bss
    .balign 16
usr1_runs:    .quad 0
usr2_runs:    .quad 0
sigaction:    .skip 32  # handler, flags, restorer, mask

    .section .text
_start:
    mov     qword ptr [rip + sigaction + 8], SA_RESTORER
    lea     rax, [rip + restorer]
    mov     [rip + sigaction + 16], rax
    mov     qword ptr [rip + sigaction + 24], 0

    lea     rax, [rip + usr1_handler]
    mov     [rip + sigaction], rax
    mov     eax, SYS_RT_SIGACTION  # rt_sigaction(SIGUSR1, &act, NULL, 8)
    mov     edi, SIGUSR1
    lea     rsi, [rip + sigaction]
    xor     edx, edx
    mov     r10d, 8
    syscall
    test    rax, rax
    jnz     sigaction_failed

    lea     rax, [rip + usr2_handler]
    mov     [rip + sigaction], rax
    mov     eax, SYS_RT_SIGACTION  # rt_sigaction(SIGUSR2, &act, NULL, 8)
    mov     edi, SIGUSR2
    lea     rsi, [rip + sigaction]
    xor     edx, edx
    mov     r10d, 8
    syscall
    test    rax, rax
    jnz     sigaction_failed

    mov     eax, SYS_GETTID
    syscall
    mov     r12, rax

    mov     eax, SYS_TKILL  # tkill(tid, SIGUSR1)
    mov     rdi, r12
    mov     esi, SIGUSR1
    syscall
    test    rax, rax
    jnz     tkill_failed

    mov     eax, SYS_TKILL  # tkill(tid, SIGUSR2)
    mov     rdi, r12
    mov     esi, SIGUSR2
    syscall
    test    rax, rax
    jnz     tkill_failed

    cmp     qword ptr [rip + usr1_runs], 1
    jne     usr1_not_once
    cmp     qword ptr [rip + usr2_runs], 0
    jne     usr2_ran

    mov     eax, SYS_EXIT  # exit(0)
    xor     edi, edi
    syscall
    ud2

usr1_handler:
    add     qword ptr [rip + usr1_runs], 1
    ret

usr2_handler:
    add     qword ptr [rip + usr2_runs], 1
    ret

restorer:
    mov     eax, SYS_RT_SIGRETURN
    syscall
    ud2

sigaction_failed:
    mov     edi, 60
    jmp     fail
tkill_failed:
    mov     edi, 61
    jmp     fail
usr1_not_once:
    mov     edi, 70
    jmp     fail
usr2_ran:
    mov     edi, 71
fail:
    mov     eax, SYS_EXIT
    syscall
    ud2
