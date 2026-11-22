// Direct-syscall hello-world for NARF's IA-32 compat ABI.
//
// An ELFCLASS32 EM_386 static executable: no libc, no PT_INTERP. The ELF32
// loader (userspace/src/process.rs) gives it a TASK_SIZE_32 address space
// and a 32-bit startup stack and enters it in compatibility mode
// (CS = __USER32_CS); `int 0x80` is then the i386 system-call gate, with the
// numbers of arch/x86/entry/syscalls/syscall_32.tbl: write is 4, exit_group
// is 252. Arguments go in ebx, ecx, edx.
//
// Built from this source at build time by verification/build.rs
// (`as --32`, `ld -m elf_i386`); no prebuilt binary is committed.

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    # write(1, msg, 11)
    mov     eax, 4
    mov     ebx, 1
    mov     ecx, offset msg
    mov     edx, 11
    int     0x80

    # exit_group(0)
    mov     eax, 252
    xor     ebx, ebx
    int     0x80

    # Unreachable; trap just in case.
    ud2

    .section .rodata
msg:
    .ascii "hello i386\n"

    # A non-executable stack (PT_GNU_STACK RW), as every modern toolchain
    # marks one.
    .section .note.GNU-stack,"",@progbits
