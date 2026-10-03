// Bad-frame guest: rt_sigreturn with no signal frame on an unmapped stack,
// and no SIGSEGV handler. Linux's badframe path ends in force_sig(SIGSEGV),
// so the process dies of SIGSEGV and never returns from the syscall.
//
// The kernel test's interceptor forks from inside the rt_sigreturn callback
// before the original runs. That child resumes after the syscall with
// rax == 0 and exits 42; the parent must never get there (it would exit 5).

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    mov     rsp, 0x1000         # unmapped: the frame cannot be read
    mov     eax, 15             # rt_sigreturn
    syscall
    test    rax, rax
    jnz     parent_survived
    mov     edi, 42             # the fork child: exit(42)
    mov     eax, 60
    syscall
    ud2
parent_survived:
    mov     edi, 5
    mov     eax, 60
    syscall
    ud2
