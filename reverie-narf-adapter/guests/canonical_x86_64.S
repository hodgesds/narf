// One libc-free x86_64 Linux guest shared by the Hermit/Narf equivalence POC.
// It deliberately uses the modern `syscall` instruction on both kernels.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    // write(1, message, message_len)
    mov     eax, 1
    mov     edi, 1
    lea     rsi, [rip + message]
    mov     edx, message_end - message
    syscall
    cmp     rax, message_end - message
    jne     failed

    // exit(0)
    mov     eax, 60
    xor     edi, edi
    syscall

failed:
    mov     eax, 60
    mov     edi, 111
    syscall
    ud2

    .section .rodata
message:
    .ascii "narf-hermit-poc\n"
message_end:
