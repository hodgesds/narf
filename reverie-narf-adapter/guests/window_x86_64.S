// Window guest: the user half between 0x80_4000_0000 and 0x100_0000_0000
// (PML4[1] outside its first GiB) behaves as ordinary unmapped user address
// space. Narf once shared its kernel's supervisor-only 1 GiB identity pages
// for physical 513 GiB..1 TiB into every user address space there, so mmap
// accepted a fixed mapping the first user store then faulted on, and read(2)
// and write(2) copied to and from physical memory at a caller-chosen window
// address with no mapping at all.
//
// The guest makes each observation once and reports its raw result as one
// little-endian 8-byte word on fd 1, in this order:
//
//   0  write(4, PROBE, 16) with nothing mapped at PROBE        Linux: -EFAULT
//   1  read(3, PROBE, 16) with 16 bytes queued                 Linux: -EFAULT
//   2  read(3, buffer, 64): what the faulting read left        Linux: 16
//   3  1 if those bytes are the 16 queued pattern bytes, else 0
//   4  mmap(WINDOW, 4096, RW, PRIVATE|ANON|FIXED_NOREPLACE)    Linux: WINDOW
//   5  1 if user stores at both ends of WINDOW read back      (a fault here
//      unchanged, else 0                                       ends the guest)
//   6  write(4, WINDOW, 16) from the new page                  Linux: 16
//   7  1 if read(3, buffer, 16) returns exactly those bytes, else 0
//   8  1 if the parent still reads its own values at both ends of WINDOW
//      after a forked child overwrote them and exited, else 0
//   9  the child's wait status                                 Linux: 0
//  10  munmap(WINDOW, 4096)                                    Linux: 0
//  11  write(4, WINDOW, 16) after the unmap                    Linux: -EFAULT
//
// It then exits 0; the kernel test judges the words. Only failures of the
// scaffolding itself (the pipe, the report writes, fork, wait4) exit with a
// status in 120..=124. The child exits 1 if its own stores do not read
// back. The pipe is non-blocking, so a read that consumed the queued bytes
// despite faulting shows up as -EAGAIN in word 2 rather than a hang.
//
// PROBE (0x90_0000_0000, 576 GiB) is chosen clear of every PCI BAR on the
// QEMU q35 machine the tests boot (all BARs sit below 4 GiB) and of guest
// RAM (1 GiB), so a kernel that still copies through the old identity pages
// touches no device. WINDOW is the address the finding reported.

    .intel_syntax noprefix
    .global _start
    .section .text

    .set PROBE, 0x9000000000
    .set WINDOW, 0x8100000000
    .set PAGE, 4096
    .set O_NONBLOCK, 0x800
    .set MAP_PRIVATE_ANON_NOREPLACE, 0x100022

_start:
    sub     rsp, 16
    mov     eax, 293            # pipe2(fds, O_NONBLOCK)
    mov     rdi, rsp
    mov     esi, O_NONBLOCK
    syscall
    test    rax, rax
    jnz     pipe_failed
    cmp     dword ptr [rsp], 3
    jne     fds_unexpected
    cmp     dword ptr [rsp + 4], 4
    jne     fds_unexpected

    mov     eax, 1              # 0: write(4, PROBE, 16)
    mov     edi, 4
    mov     rsi, PROBE
    mov     edx, 16
    syscall
    call    report

    mov     eax, 1              # queue the pattern: write(4, pattern, 16)
    mov     edi, 4
    lea     rsi, [rip + pattern]
    mov     edx, 16
    syscall
    cmp     rax, 16
    jne     pipe_failed

    xor     eax, eax            # 1: read(3, PROBE, 16)
    mov     edi, 3
    mov     rsi, PROBE
    mov     edx, 16
    syscall
    call    report

    xor     eax, eax            # 2: read(3, buffer, 64)
    mov     edi, 3
    lea     rsi, [rip + buffer]
    mov     edx, 64
    syscall
    call    report
    lea     rsi, [rip + buffer] # 3: buffer[0..16] == pattern
    lea     rdi, [rip + pattern]
    call    same16
    call    report

    mov     eax, 9              # 4: mmap(WINDOW, PAGE, RW, ..., -1, 0)
    mov     rdi, WINDOW
    mov     esi, PAGE
    mov     edx, 3
    mov     r10d, MAP_PRIVATE_ANON_NOREPLACE
    mov     r8, -1
    xor     r9d, r9d
    syscall
    call    report

    mov     rdi, WINDOW         # 5: user stores at both ends read back
    mov     rax, 0x0123456789abcdef
    mov     qword ptr [rdi], rax
    not     rax
    mov     qword ptr [rdi + 8], rax
    mov     qword ptr [rdi + PAGE - 8], rax
    xor     ecx, ecx
    cmp     qword ptr [rdi + PAGE - 8], rax
    jne     1f
    not     rax
    cmp     qword ptr [rdi], rax
    jne     1f
    inc     ecx
1:  mov     eax, ecx
    call    report

    mov     eax, 1              # 6: write(4, WINDOW, 16)
    mov     edi, 4
    mov     rsi, WINDOW
    mov     edx, 16
    syscall
    call    report
    xor     eax, eax            # 7: read(3, buffer, 16) == WINDOW[0..16]
    mov     edi, 3
    lea     rsi, [rip + buffer]
    mov     edx, 16
    syscall
    cmp     rax, 16
    jne     2f
    lea     rsi, [rip + buffer]
    mov     rdi, WINDOW
    call    same16
    jmp     3f
2:  xor     eax, eax
3:  call    report

    mov     eax, 57             # 8: fork; the child overwrites WINDOW
    syscall
    test    rax, rax
    js      fork_failed
    jz      child
    mov     rdi, rax            # wait4(pid, &status, 0, NULL)
    mov     r12, rax
    mov     eax, 61
    lea     rsi, [rsp + 8]
    xor     edx, edx
    xor     r10d, r10d
    syscall
    cmp     rax, r12
    jne     wait_failed
    mov     rdi, WINDOW
    mov     rax, 0x0123456789abcdef
    xor     ecx, ecx
    cmp     qword ptr [rdi], rax
    jne     5f
    not     rax
    cmp     qword ptr [rdi + PAGE - 8], rax
    jne     5f
    inc     ecx
5:  mov     eax, ecx
    call    report
    mov     eax, dword ptr [rsp + 8] # 9: the child's wait status
    call    report

    mov     eax, 11             # 10: munmap(WINDOW, PAGE)
    mov     rdi, WINDOW
    mov     esi, PAGE
    syscall
    call    report

    mov     eax, 1              # 11: write(4, WINDOW, 16) after the unmap
    mov     edi, 4
    mov     rsi, WINDOW
    mov     edx, 16
    syscall
    call    report

    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

// The forked child: overwrite both ends of its copy of WINDOW, check the
// stores read back, and exit 0 (1 if they do not).
child:
    mov     rdi, WINDOW
    mov     rax, 0x5a5a5a5a5a5a5a5a
    mov     qword ptr [rdi], rax
    mov     qword ptr [rdi + PAGE - 8], rax
    xor     edi, edi
    mov     rsi, WINDOW
    cmp     qword ptr [rsi], rax
    setne   dil
    cmp     qword ptr [rsi + PAGE - 8], rax
    jne     6f
    jmp     die
6:  mov     edi, 1
    jmp     die

// rax = 1 if the 16 bytes at rsi equal the 16 bytes at rdi, else 0.
same16:
    mov     rax, qword ptr [rsi]
    cmp     rax, qword ptr [rdi]
    jne     4f
    mov     rax, qword ptr [rsi + 8]
    cmp     rax, qword ptr [rdi + 8]
    jne     4f
    mov     eax, 1
    ret
4:  xor     eax, eax
    ret

// Writes rax to fd 1 as one 8-byte word.
report:
    mov     qword ptr [rip + report_word], rax
    mov     eax, 1
    mov     edi, 1
    lea     rsi, [rip + report_word]
    mov     edx, 8
    syscall
    cmp     rax, 8
    jne     report_failed
    ret

pipe_failed:
    mov     edi, 120
    jmp     die
fds_unexpected:
    mov     edi, 121
    jmp     die
report_failed:
    mov     edi, 122
    jmp     die
fork_failed:
    mov     edi, 123
    jmp     die
wait_failed:
    mov     edi, 124
die:
    mov     eax, 60
    syscall
    ud2

    .section .rodata
pattern:
    .ascii  "window-f1-probe\n"

    .section .bss
    .balign 16
report_word:
    .skip   8
    .balign 16
buffer:
    .skip   64
