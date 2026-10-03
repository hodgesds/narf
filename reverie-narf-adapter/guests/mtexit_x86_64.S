// Thread exit-status guest. Any unexpected result exits with a distinct
// status in 50..=54.
//
// 1. fork a child process. Its leader stores 1 in `leader_word`, names it
//    with set_tid_address, starts a thread and calls exit(3); the thread
//    futex-waits until the kernel clears `leader_word` at the leader's exit,
//    then calls exit(5), so the process's last thread exits after its leader.
// 2. The parent reaps the child and requires wait status 0x500: with no
//    group exit, Linux reports the last exiting thread's own code
//    (synchronize_group_exit), not the leader's.
// 3. The parent starts a thread that calls exit(6), waits for the kernel to
//    clear `thread_word` at that thread's exit, and calls exit_group(7).

    .intel_syntax noprefix
    .global _start

    .equ SYS_EXIT, 60
    .equ SYS_EXIT_GROUP, 231
    .equ SYS_FORK, 57
    .equ SYS_WAIT4, 61
    .equ SYS_CLONE, 56
    .equ SYS_FUTEX, 202
    .equ SYS_SET_TID_ADDRESS, 218
    // CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM
    .equ THREAD_FLAGS, 0x50f00
    // THREAD_FLAGS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
    .equ THREAD_FLAGS_CLEARTID, 0x350f00

    .section .bss
    .balign 16
leader_word:  .quad 0
thread_word:  .quad 0
status_word:  .quad 0
    .balign 16
    .skip 4096
thread_stack_top:

    .section .text
_start:
    mov     eax, SYS_FORK
    syscall
    test    rax, rax
    js      fork_failed
    jnz     parent

// ── child process: leader exits first, its thread last ──
    mov     dword ptr [rip + leader_word], 1
    lea     rdi, [rip + leader_word]
    mov     eax, SYS_SET_TID_ADDRESS
    syscall
    mov     edi, THREAD_FLAGS
    lea     rsi, [rip + thread_stack_top]
    xor     edx, edx
    xor     r10d, r10d
    xor     r8d, r8d
    mov     eax, SYS_CLONE
    syscall
    test    rax, rax
    js      child_clone_failed
    jz      child_thread
    mov     eax, SYS_EXIT       # leader: exit(3)
    mov     edi, 3
    syscall
    ud2

child_thread:
    lea     rdi, [rip + leader_word]
    call    wait_cleared
    mov     eax, SYS_EXIT       # last thread: exit(5)
    mov     edi, 5
    syscall
    ud2

// ── parent ──
parent:
    mov     rdi, rax            # wait4(child, &status, 0, NULL)
    lea     rsi, [rip + status_word]
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, SYS_WAIT4
    syscall
    test    rax, rax
    js      wait_failed
    cmp     dword ptr [rip + status_word], 0x0500
    jne     child_status_bad

    mov     edi, THREAD_FLAGS_CLEARTID
    lea     rsi, [rip + thread_stack_top]
    lea     rdx, [rip + thread_word]    # parent_tid: nonzero before the thread runs
    lea     r10, [rip + thread_word]    # child_tid: cleared at the thread's exit
    xor     r8d, r8d
    mov     eax, SYS_CLONE
    syscall
    test    rax, rax
    js      parent_clone_failed
    jz      parent_thread
    lea     rdi, [rip + thread_word]
    call    wait_cleared
    mov     eax, SYS_EXIT_GROUP # exit_group(7)
    mov     edi, 7
    syscall
    ud2

parent_thread:
    mov     eax, SYS_EXIT       # exit(6)
    mov     edi, 6
    syscall
    ud2

// Futex-waits until the 32-bit word at rdi is zero. Clobbers rax, rsi, rdx,
// r10, r8, r9, rcx, r11, r12.
wait_cleared:
    mov     r12, rdi
1:
    mov     edx, dword ptr [r12]
    test    edx, edx
    jz      2f
    mov     rdi, r12            # futex(word, FUTEX_WAIT, seen, NULL)
    xor     esi, esi
    xor     r10d, r10d
    mov     eax, SYS_FUTEX
    syscall
    jmp     1b
2:
    ret

fork_failed:
    mov     edi, 50
    jmp     die
child_clone_failed:
    mov     edi, 51
    jmp     die
wait_failed:
    mov     edi, 52
    jmp     die
child_status_bad:
    mov     edi, 53
    jmp     die
parent_clone_failed:
    mov     edi, 54
die:
    mov     eax, SYS_EXIT_GROUP
    syscall
    ud2
