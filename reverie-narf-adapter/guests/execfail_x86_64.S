// Failed-exec guest: three execve calls that each fail back to the guest,
// then exit(0). The kernel test mounts, under /rn-exec, "junk" (64 bytes that
// are not an ELF) and "nointerp" (guests/nointerp_x86_64.S, whose PT_INTERP
// names a missing file), and nothing at "missing". An execve that does not
// return its errno ends the guest with that call's code: 1 unless "missing"
// returns -ENOENT, 2 unless "junk" returns -ENOEXEC, 3 unless "nointerp"
// returns -ENOENT.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    lea     rdi, [rip + path_missing]
    lea     rsi, [rip + argv_missing]
    lea     rdx, [rip + envp]
    mov     eax, 59             # execve
    syscall
    mov     edi, 1
    cmp     rax, -2             # -ENOENT
    jne     fail
    lea     rdi, [rip + path_junk]
    lea     rsi, [rip + argv_junk]
    lea     rdx, [rip + envp]
    mov     eax, 59             # execve
    syscall
    mov     edi, 2
    cmp     rax, -8             # -ENOEXEC
    jne     fail
    lea     rdi, [rip + path_nointerp]
    lea     rsi, [rip + argv_nointerp]
    lea     rdx, [rip + envp]
    mov     eax, 59             # execve
    syscall
    mov     edi, 3
    cmp     rax, -2             # -ENOENT
    jne     fail
    xor     edi, edi
fail:
    mov     eax, 60             # exit(edi)
    syscall
    ud2

    .section .rodata
path_missing:
    .asciz  "/rn-exec/missing"
path_junk:
    .asciz  "/rn-exec/junk"
path_nointerp:
    .asciz  "/rn-exec/nointerp"

    .section .data
    .balign 8
argv_missing:
    .quad   path_missing
    .quad   0
argv_junk:
    .quad   path_junk
    .quad   0
argv_nointerp:
    .quad   path_nointerp
    .quad   0
envp:
    .quad   0
