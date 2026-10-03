// Reaping-parent guest for the Narf parity cell. The harness publishes the
// cell's root as this process's child before either runs; this process then
// reaps it through the kernel's wait4, as a Linux parent would, and reports
// what wait4 returned on fd 1 as 16 raw bytes:
//   bytes 0..8   the first wait4's return value (the reaped pid), i64 LE
//   bytes 8..12  the status word wait4 stored, i32 LE; it holds the sentinel
//                0xdeadbeef if the kernel never stored one
//   bytes 12..16 the second wait4's return value, i32 LE; -ECHILD (-10)
//                once the only child has been reaped
// It exits 0 once the report is written, 112 if the write fell short.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    sub     rsp, 32
    mov     dword ptr [rsp + 8], 0xdeadbeef

    mov     rdi, -1             # wait4(-1, &status, 0, NULL)
    lea     rsi, [rsp + 8]
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    mov     qword ptr [rsp], rax

    mov     rdi, -1             # wait4(-1, &scratch, 0, NULL): no child left
    lea     rsi, [rsp + 16]
    xor     edx, edx
    xor     r10d, r10d
    mov     eax, 61
    syscall
    mov     dword ptr [rsp + 12], eax

    mov     eax, 1              # write(1, report, 16)
    mov     edi, 1
    mov     rsi, rsp
    mov     edx, 16
    syscall
    cmp     rax, 16
    jne     failed

    mov     eax, 60             # exit(0)
    xor     edi, edi
    syscall
    ud2

failed:
    mov     eax, 60
    mov     edi, 112
    syscall
    ud2
