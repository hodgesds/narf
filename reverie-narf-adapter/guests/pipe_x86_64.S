// Pipe guest: a forked child fills a pipe to capacity (64 KiB) and then
// writes one more byte, which cannot complete until someone reads. The parent
// reads the pipe only after a byte arrives on a second, gate pipe, which the
// kernel test writes once it has seen the child's one-byte write park. The
// parent then drains the data pipe to EOF, expects exactly 65537 bytes, reaps
// the child, and exits 0. Any unexpected result exits with a distinct status
// in 120..=130.
//
// File descriptors are fixed so the test can find the gate: data pipe 3
// (read) / 4 (write), gate pipe 5 (read) / 6 (write).

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    sub     rsp, 16

    mov     eax, 293            # pipe2(&fds[0], 0): data pipe
    mov     rdi, rsp
    xor     esi, esi
    syscall
    test    rax, rax
    jnz     pipe_failed
    mov     eax, 293            # pipe2(&fds[2], 0): gate pipe
    lea     rdi, [rsp + 8]
    xor     esi, esi
    syscall
    test    rax, rax
    jnz     pipe_failed
    cmp     dword ptr [rsp], 3
    jne     fds_unexpected
    cmp     dword ptr [rsp + 4], 4
    jne     fds_unexpected
    cmp     dword ptr [rsp + 8], 5
    jne     fds_unexpected
    cmp     dword ptr [rsp + 12], 6
    jne     fds_unexpected

    mov     eax, 57             # fork()
    syscall
    test    rax, rax
    js      fork_failed
    jnz     parent

    xor     r12d, r12d          # child: bytes written so far
fill:
    mov     eax, 1              # write(4, buffer, 65536 - written)
    mov     edi, 4
    lea     rsi, [rip + buffer]
    mov     edx, 65536
    sub     edx, r12d
    syscall
    test    rax, rax
    jle     fill_failed
    add     r12, rax
    cmp     r12, 65536
    jb      fill
    mov     eax, 1              # write(4, buffer, 1): the pipe is full
    mov     edi, 4
    lea     rsi, [rip + buffer]
    mov     edx, 1
    syscall
    cmp     rax, 1
    jne     extra_failed
    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

parent:
    mov     r13, rax            # the child's pid
    mov     eax, 3              # close(4): EOF follows the child's exit
    mov     edi, 4
    syscall
    test    rax, rax
    jnz     close_failed
    xor     eax, eax            # read(5, gate, 1): wait for the gate
    mov     edi, 5
    lea     rsi, [rip + gate]
    mov     edx, 1
    syscall
    cmp     rax, 1
    jne     gate_failed
    xor     r12d, r12d          # bytes drained so far
drain:
    xor     eax, eax            # read(3, buffer, 0x20000)
    mov     edi, 3
    lea     rsi, [rip + buffer]
    mov     edx, 0x20000
    syscall
    test    rax, rax
    js      drain_failed
    jz      drained
    add     r12, rax
    jmp     drain
drained:
    cmp     r12, 65537
    jne     drain_short
    mov     rdi, r13            # wait4(child, &status, 0, NULL)
    mov     rsi, rsp
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    cmp     rax, r13
    jne     wait_failed
    cmp     dword ptr [rsp], 0
    jne     child_status_bad
    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

pipe_failed:
    mov     edi, 120
    jmp     die
fds_unexpected:
    mov     edi, 121
    jmp     die
fork_failed:
    mov     edi, 122
    jmp     die
fill_failed:
    mov     edi, 123
    jmp     die
extra_failed:
    mov     edi, 124
    jmp     die
close_failed:
    mov     edi, 125
    jmp     die
gate_failed:
    mov     edi, 126
    jmp     die
drain_failed:
    mov     edi, 127
    jmp     die
drain_short:
    mov     edi, 128
    jmp     die
wait_failed:
    mov     edi, 129
    jmp     die
child_status_bad:
    mov     edi, 130
die:
    mov     eax, 60
    syscall
    ud2

    .section .bss
    .balign 4096
buffer:
    .skip   0x20000
gate:
    .skip   16
