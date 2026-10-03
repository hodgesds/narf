// Kill-during-wait guest: fork, then the child calls getuid, whose Tool
// callback waits for something that never happens. The parent calls getgid,
// which the Tool answers with 0x4b31 once the child's callback is waiting,
// then kills the child with SIGKILL, reaps it, checks that it died of
// signal 9, and exits 0. A child that returns from getuid exits 119. Any
// other unexpected result exits with a distinct status in 113..=118.

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
    mov     eax, 102            # child: getuid(), which never returns
    syscall
    mov     edi, 119
    jmp     die

parent:
    mov     r12, rax            # the child's pid
    mov     eax, 104            # getgid()
    syscall
    cmp     rax, 0x4b31
    jne     parent_value_bad
    mov     rdi, r12            # kill(child, SIGKILL)
    mov     esi, 9
    mov     eax, 62
    syscall
    test    rax, rax
    jnz     kill_failed
    mov     rdi, r12            # wait4(child, &status, 0, NULL)
    mov     rsi, rsp
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    cmp     rax, r12
    jne     wait_failed
    cmp     dword ptr [rsp], 9
    jne     child_status_bad

    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

fork_failed:
    mov     edi, 113
    jmp     die
parent_value_bad:
    mov     edi, 115
    jmp     die
kill_failed:
    mov     edi, 116
    jmp     die
wait_failed:
    mov     edi, 117
    jmp     die
child_status_bad:
    mov     edi, 118
die:
    mov     eax, 60
    syscall
    ud2
