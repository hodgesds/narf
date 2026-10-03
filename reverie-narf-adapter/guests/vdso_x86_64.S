// vDSO guest: finds the vDSO through AT_SYSINFO_EHDR and its .dynsym, as a
// libc does, then calls __vdso_clock_gettime(CLOCK_MONOTONIC, &ts),
// __vdso_gettimeofday(&tv, NULL), __vdso_time(NULL) and
// __vdso_getcpu(&cpu, &node, NULL), in that order, and exits 0.
//
// It exits 0 only if time() returned 4242, the value the VdsoCalls Tool
// supplies for the time syscall, so a vDSO that answered from the counter
// (the Tool never saw the call) makes it exit 20. Other exits:
//   10  no AT_SYSINFO_EHDR in the auxiliary vector
//   11  a __vdso_* symbol is missing
//   21  clock_gettime failed; 22 gettimeofday failed; 23 getcpu failed

    .intel_syntax noprefix
    .global _start
    .section .text

_start:
    // Skip argc, argv[] and its NULL, then envp[] and its NULL.
    mov     rbx, rsp
    mov     rcx, [rbx]
    lea     rbx, [rbx + rcx*8 + 16]
1:
    mov     rax, [rbx]
    add     rbx, 8
    test    rax, rax
    jnz     1b
    // rbx: the auxiliary vector.
2:
    mov     rax, [rbx]
    test    rax, rax
    jz      no_vdso
    cmp     rax, 33                 # AT_SYSINFO_EHDR
    je      3f
    add     rbx, 16
    jmp     2b
3:
    mov     r12, [rbx + 8]          # r12: the vDSO ELF header

    lea     rdi, [rip + name_clock_gettime]
    call    lookup
    test    rax, rax
    jz      missing
    mov     edi, 1                  # CLOCK_MONOTONIC
    lea     rsi, [rip + ts]
    call    rax
    test    eax, eax
    jnz     clock_failed

    lea     rdi, [rip + name_gettimeofday]
    call    lookup
    test    rax, rax
    jz      missing
    lea     rdi, [rip + tv]
    xor     esi, esi
    call    rax
    test    eax, eax
    jnz     gtod_failed

    lea     rdi, [rip + name_time]
    call    lookup
    test    rax, rax
    jz      missing
    xor     edi, edi
    call    rax
    cmp     rax, 4242
    jne     time_wrong

    lea     rdi, [rip + name_getcpu]
    call    lookup
    test    rax, rax
    jz      missing
    lea     rdi, [rip + cpu]
    lea     rsi, [rip + node]
    xor     edx, edx
    call    rax
    test    eax, eax
    jnz     getcpu_failed

    xor     edi, edi
    jmp     exit
no_vdso:
    mov     edi, 10
    jmp     exit
missing:
    mov     edi, 11
    jmp     exit
time_wrong:
    mov     edi, 20
    jmp     exit
clock_failed:
    mov     edi, 21
    jmp     exit
gtod_failed:
    mov     edi, 22
    jmp     exit
getcpu_failed:
    mov     edi, 23
exit:
    mov     eax, 231                # exit_group
    syscall
    ud2

// lookup: rdi = NUL-terminated symbol name, r12 = vDSO ELF header.
// Returns rax = r12 + st_value of the first SHT_DYNSYM symbol with that
// name, or 0. The vDSO is linked at 0 and mapped as its raw file image, so
// file offsets and symbol values are both offsets from r12.
lookup:
    push    rbx
    push    rbp
    push    r13
    push    r14
    push    r15
    mov     r13, [r12 + 0x28]       # e_shoff
    add     r13, r12                # r13: section headers
    movzx   r14, word ptr [r12 + 0x3a]  # e_shentsize
    movzx   r15, word ptr [r12 + 0x3c]  # e_shnum
    xor     ecx, ecx                # section index
.Lsection:
    cmp     rcx, r15
    jae     .Lnone
    mov     rax, rcx
    imul    rax, r14
    lea     rbx, [r13 + rax]        # rbx: this section header
    cmp     dword ptr [rbx + 4], 11 # sh_type == SHT_DYNSYM
    jne     .Lnext_section
    mov     rsi, [rbx + 24]         # sh_offset
    add     rsi, r12                # rsi: first symbol
    mov     rbp, [rbx + 32]         # sh_size
    add     rbp, rsi                # rbp: end of the symbols
    mov     eax, dword ptr [rbx + 40]   # sh_link: the string table
    imul    rax, r14
    mov     r8, [r13 + rax + 24]
    add     r8, r12                 # r8: the string table
.Lsymbol:
    cmp     rsi, rbp
    jae     .Lnext_section
    mov     eax, dword ptr [rsi]    # st_name
    lea     r9, [r8 + rax]
    mov     r10, rdi
.Lcompare:
    mov     al, [r9]
    cmp     al, [r10]
    jne     .Lnext_symbol
    test    al, al
    jz      .Lfound
    inc     r9
    inc     r10
    jmp     .Lcompare
.Lnext_symbol:
    add     rsi, 24
    jmp     .Lsymbol
.Lfound:
    mov     rax, [rsi + 8]          # st_value
    add     rax, r12
    jmp     .Lout
.Lnext_section:
    inc     rcx
    jmp     .Lsection
.Lnone:
    xor     eax, eax
.Lout:
    pop     r15
    pop     r14
    pop     r13
    pop     rbp
    pop     rbx
    ret

    .section .rodata
name_clock_gettime:
    .asciz  "__vdso_clock_gettime"
name_gettimeofday:
    .asciz  "__vdso_gettimeofday"
name_time:
    .asciz  "__vdso_time"
name_getcpu:
    .asciz  "__vdso_getcpu"

    .section .bss
    .balign 16
ts:
    .skip   16
tv:
    .skip   16
cpu:
    .skip   4
node:
    .skip   4
