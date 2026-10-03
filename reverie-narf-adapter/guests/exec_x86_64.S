// Exec guest: execve("/rn-exec/prog", ["/rn-exec/prog"], []) and nothing
// else. The kernel test mounts the canonical guest at that path, so a
// successful exec writes the canonical message and exits 0; a failed exec
// exits 3.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    lea     rdi, [rip + path]
    lea     rsi, [rip + argv]
    lea     rdx, [rip + envp]
    mov     eax, 59             # execve
    syscall
    mov     eax, 60             # exit(3)
    mov     edi, 3
    syscall
    ud2

    .section .rodata
path:
    .asciz  "/rn-exec/prog"

    .section .data
    .balign 8
argv:
    .quad   path
    .quad   0
envp:
    .quad   0
