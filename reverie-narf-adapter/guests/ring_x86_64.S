// Ring guest: a file write the kernel performs on the task's behalf.
//
// It opens a pipe (fds 3 and 4), bootstraps its shared submission and
// completion rings (Narf syscall 0x4001), queues one Write submission for
// the pipe's write end and kicks the ring (0x4003). The kernel runs that
// write inside the kick, through its own syscall entry. The guest then
// checks the completion and reads the bytes back from the pipe, and exits
// 0. Each failed check exits with its own status in 120..129.
//
// Ring layout (user-runtime's testbin documents the same): a SharedRing is
// head u32 at 0, tail u32 at 4, slots from 64. A Submission is op u32 at 0,
// tag u64 at 80, inline[6] u64 from 88, 144 bytes. A Completion is tag u64
// at 0, status u32 at 8, result[6] u64 from 16.

    .intel_syntax noprefix
    .global _start
    .section .text

    .set MSG_LEN, 11

_start:
    lea     rdi, [rip + fds]    # pipe2(fds, 0)
    xor     esi, esi
    mov     eax, 293
    syscall
    test    rax, rax
    jnz     fail120
    cmp     dword ptr [rip + fds], 3
    jne     fail121
    cmp     dword ptr [rip + fds + 4], 4
    jne     fail121

    mov     eax, 0x4001         # bootstrap
    syscall
    test    rax, rax
    jz      fail122
    cmp     rax, -4095          # any errno return, unsigned [-4095, -1]
    jae     fail122
    cmp     dword ptr [rax], 0x4E415246
    jne     fail123
    mov     r12, [rax + 40]     # shared SQ
    mov     r13, [rax + 48]     # shared CQ

    lea     rdi, [r12 + 64]     # SQ slot 0 := Write(4, msg, MSG_LEN)
    xor     eax, eax
    mov     ecx, 18
    rep stosq
    mov     dword ptr [r12 + 64], 0x12
    mov     rax, 0xFEED
    mov     [r12 + 64 + 80], rax
    mov     qword ptr [r12 + 64 + 88], 4
    lea     rax, [rip + msg]
    mov     [r12 + 64 + 96], rax
    mov     qword ptr [r12 + 64 + 104], MSG_LEN
    mfence
    mov     dword ptr [r12], 1  # SQ head

    mov     eax, 0x4003         # ring kick
    syscall
    cmp     rax, 1
    jne     fail124
    cmp     dword ptr [r13], 1  # one completion
    jne     fail125
    mov     rax, 0xFEED
    cmp     [r13 + 64], rax
    jne     fail126
    cmp     dword ptr [r13 + 64 + 8], 0
    jne     fail126
    cmp     qword ptr [r13 + 64 + 16], MSG_LEN
    jne     fail127
    mov     dword ptr [r13 + 4], 1

    mov     edi, 3              # read(3, buf, 64)
    lea     rsi, [rip + buf]
    mov     edx, 64
    xor     eax, eax
    syscall
    cmp     rax, MSG_LEN
    jne     fail128
    lea     rsi, [rip + buf]
    lea     rdi, [rip + msg]
    mov     ecx, MSG_LEN
    repe cmpsb
    jne     fail129

    xor     edi, edi
    jmp     exit
fail120: mov edi, 120
    jmp     exit
fail121: mov edi, 121
    jmp     exit
fail122: mov edi, 122
    jmp     exit
fail123: mov edi, 123
    jmp     exit
fail124: mov edi, 124
    jmp     exit
fail125: mov edi, 125
    jmp     exit
fail126: mov edi, 126
    jmp     exit
fail127: mov edi, 127
    jmp     exit
fail128: mov edi, 128
    jmp     exit
fail129: mov edi, 129
exit:
    mov     eax, 60
    syscall
    ud2

    .section .rodata
msg:
    .ascii  "ring-write\n"

    .section .bss
    .balign 8
fds:
    .skip   8
buf:
    .skip   64
