// Signal-interrupted park guest: installs a SIGUSR1 handler, then blocks in
// read(2) on an empty pipe and exits 0 once the read returns the one byte.
// The handler calls getpid, writes one byte into the pipe and returns
// through rt_sigreturn, so a SIGUSR1 during the blocked read ends it.
// Any unexpected result exits with a distinct status in 60..=62.

    .intel_syntax noprefix
    .global _start

    .equ SYS_READ, 0
    .equ SYS_WRITE, 1
    .equ SYS_RT_SIGACTION, 13
    .equ SYS_RT_SIGRETURN, 15
    .equ SYS_GETPID, 39
    .equ SYS_EXIT, 60
    .equ SYS_PIPE2, 293
    .equ SIGUSR1, 10
    .equ SA_RESTORER, 0x04000000

    .section .bss
    .balign 16
pipe_fds:     .quad 0  # int[2]: read end, write end
read_byte:    .quad 0
sigaction:    .skip 32  # handler, flags, restorer, mask

    .section .rodata
handler_byte: .byte 'u'

    .section .text
_start:
    lea     rax, [rip + handler]
    mov     [rip + sigaction], rax
    mov     qword ptr [rip + sigaction + 8], SA_RESTORER
    lea     rax, [rip + restorer]
    mov     [rip + sigaction + 16], rax
    mov     qword ptr [rip + sigaction + 24], 0

    mov     eax, SYS_RT_SIGACTION  # rt_sigaction(SIGUSR1, &act, NULL, 8)
    mov     edi, SIGUSR1
    lea     rsi, [rip + sigaction]
    xor     edx, edx
    mov     r10d, 8
    syscall
    test    rax, rax
    jnz     sigaction_failed

    mov     eax, SYS_PIPE2  # pipe2(pipe_fds, 0)
    lea     rdi, [rip + pipe_fds]
    xor     esi, esi
    syscall
    test    rax, rax
    jnz     pipe_failed

    mov     eax, SYS_READ  # read(pipe_fds[0], &read_byte, 1)
    mov     edi, dword ptr [rip + pipe_fds]
    lea     rsi, [rip + read_byte]
    mov     edx, 1
    syscall
    cmp     rax, 1
    jne     read_failed

    mov     eax, SYS_EXIT  # exit(0)
    xor     edi, edi
    syscall
    ud2

handler:
    mov     eax, SYS_GETPID
    syscall
    mov     eax, SYS_WRITE  # write(pipe_fds[1], &handler_byte, 1)
    mov     edi, dword ptr [rip + pipe_fds + 4]
    lea     rsi, [rip + handler_byte]
    mov     edx, 1
    syscall
    ret

restorer:
    mov     eax, SYS_RT_SIGRETURN
    syscall
    ud2

sigaction_failed:
    mov     edi, 60
    jmp     fail
pipe_failed:
    mov     edi, 61
    jmp     fail
read_failed:
    mov     edi, 62
fail:
    mov     eax, SYS_EXIT
    syscall
    ud2
