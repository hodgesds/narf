// Vfork-wait guest: the fork guest with its vfork(2) replaced by
// clone(CLONE_VM | CLONE_VFORK | SIGCHLD, stack 0), the clone that suspends
// the parent until the child exits or execs. (Narf serves syscall 58, vfork,
// with its fork handler, so only the clone form reaches the vfork wait.)
// Fork a child that exits 7 and reap it, then clone-vfork a child that spins
// and exits 9 and reap it, then exit 0. Any unexpected result exits with a
// distinct status in 113..=118.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    sub     rsp, 16

    mov     eax, 57             # fork()
    syscall
    test    rax, rax
    js      fork_failed
    jnz     fork_parent
    mov     eax, 60             # child: exit(7)
    mov     edi, 7
    syscall
    ud2

fork_parent:
    mov     rdi, rax            # wait4(child, &status, 0, NULL)
    mov     rsi, rsp
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    test    rax, rax
    js      fork_wait_failed
    cmp     dword ptr [rsp], 0x0700
    jne     fork_status_bad

    mov     edi, 0x4111         # clone(CLONE_VM|CLONE_VFORK|SIGCHLD, 0, 0, 0, 0)
    xor     esi, esi
    xor     edx, edx
    xor     r10d, r10d
    xor     r8d, r8d
    mov     eax, 56
    syscall
    test    rax, rax
    js      vfork_failed
    jnz     vfork_parent
    # child: shares the parent's memory and stack, so it touches neither.
    # It spins on registers alone (about 50 ms under KVM), so a parent the
    # kernel resumed early would reach its wait4 before this exit(9).
    mov     ecx, 0x8000000
vfork_spin:
    dec     ecx
    jnz     vfork_spin
    mov     eax, 60
    mov     edi, 9
    syscall
    ud2

vfork_parent:
    mov     rdi, rax
    mov     rsi, rsp
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    test    rax, rax
    js      vfork_wait_failed
    cmp     dword ptr [rsp], 0x0900
    jne     vfork_status_bad

    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

fork_failed:
    mov     edi, 113
    jmp     die
fork_wait_failed:
    mov     edi, 114
    jmp     die
fork_status_bad:
    mov     edi, 115
    jmp     die
vfork_failed:
    mov     edi, 116
    jmp     die
vfork_wait_failed:
    mov     edi, 117
    jmp     die
vfork_status_bad:
    mov     edi, 118
die:
    mov     eax, 60
    syscall
    ud2
