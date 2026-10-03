// Rendezvous guest: fork, then the child calls getuid and the parent calls
// getgid. A Tool meets the two callbacks through its global state and
// returns 0x5831 for the child's getuid and 0x5931 for the parent's getgid.
// The child exits 0 if its value is right. The parent checks its value,
// reaps the child, checks that it exited 0, and exits 0. Any unexpected
// result exits with a distinct status in 113..=117.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    sub     rsp, 16

    mov     eax, 57             # fork()
    syscall
    test    rax, rax
    js      fork_failed
    jnz     parent
    mov     eax, 102            # child: getuid()
    syscall
    cmp     rax, 0x5831
    jne     child_value_bad
    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

parent:
    mov     r12, rax            # the child's pid
    mov     eax, 104            # getgid()
    syscall
    cmp     rax, 0x5931
    jne     parent_value_bad
    mov     rdi, r12            # wait4(child, &status, 0, NULL)
    mov     rsi, rsp
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    cmp     rax, r12
    jne     wait_failed
    cmp     dword ptr [rsp], 0
    jne     child_status_bad

    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

fork_failed:
    mov     edi, 113
    jmp     die
child_value_bad:
    mov     edi, 114
    jmp     die
parent_value_bad:
    mov     edi, 115
    jmp     die
wait_failed:
    mov     edi, 116
    jmp     die
child_status_bad:
    mov     edi, 117
die:
    mov     eax, 60
    syscall
    ud2
