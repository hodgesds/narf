// The RDTSC guest of the reverie-narf adapter tests. It executes rdtsc
// twice and rdtscp twice, then writes the six 64-bit words it read to fd 1
// in one write: the two rdtsc values (EDX:EAX), the two rdtscp values, and
// the two rdtscp ECX values. It exits 0 if each pair of values is
// consecutive, which a Tool that counts makes them and the native counter
// never does, 1 if not, and 120 if the write did not write all 48 bytes.

    .intel_syntax noprefix
    .global _start
    .section .text
_start:
    sub     rsp, 48
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [rsp], rax
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [rsp + 8], rax
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    mov     [rsp + 16], rax
    mov     [rsp + 32], rcx
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    mov     [rsp + 24], rax
    mov     [rsp + 40], rcx
    mov     edi, 1              # write(1, rsp, 48)
    mov     rsi, rsp
    mov     edx, 48
    mov     eax, 1
    syscall
    cmp     rax, 48
    jne     write_failed
    mov     rax, [rsp]
    inc     rax
    cmp     rax, [rsp + 8]
    jne     not_consecutive
    mov     rax, [rsp + 16]
    inc     rax
    cmp     rax, [rsp + 24]
    jne     not_consecutive
    xor     edi, edi
    jmp     die
write_failed:
    mov     edi, 120
    jmp     die
not_consecutive:
    mov     edi, 1
die:
    mov     eax, 60             # exit(edi)
    syscall
    ud2
