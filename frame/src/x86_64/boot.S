/*
 * NARF x86_64 boot stub.
 *
 * Multiboot2 entry → long mode → _start_rust(magic: u64, payload: u64).
 */

.section .note.Xen, "a"
.align 4
    .long 4                         /* namesz: "Xen\0"          */
    .long 4                         /* descsz: 32-bit address   */
    .long 18                        /* XEN_ELFNOTE_PHYS32_ENTRY */
    .ascii "Xen\0"
    .long _start                    /* PVH entry point          */

/* ─── 32-bit entry ──────────────────────────────────────────────── */
.section .boot, "ax"
.code32
.global _start
.type _start, @function
_start:
    cli

    /* Stack: 64 KiB in .boot.data. */
    mov esp, offset stack_top

    /* Stash the bootloader handoff. */
    push 0
    push ebx
    push 0
    push eax

    /* ── identity-map the first 1 GiB + higher-half mapping ── */
    lea eax, [pdpt]
    or  eax, 0x3                                /* P | RW */
    
    mov [pml4], eax                             /* PML4[0] */
    mov [pml4 + 511 * 8], eax                   /* PML4[511] */

    /* PDPT[0]   = 0 | (P | RW | PS)      — identity low 1-GiB */
    /* PDPT[510] = 0 | (P | RW | PS)      — higher-half maps to phys 0 */
    mov dword ptr [pdpt], 0x83
    mov dword ptr [pdpt + 510 * 8], 0x83

    /* CR3 = &PML4 */
    mov eax, offset pml4
    mov cr3, eax

    /* CR4.PAE = 1 */
    mov eax, cr4
    or  eax, 0x20
    mov cr4, eax

    /* IA32_EFER.LME = 1 */
    mov ecx, 0xC0000080
    rdmsr
    or  eax, 0x100
    wrmsr

    /* CR0.PG = 1 */
    mov eax, cr0
    or  eax, 0x80000000
    mov cr0, eax

    /* Load our GDT and far-jump into 64-bit code. */
    lgdt [gdt_ptr]
    
    push 0x08
    mov eax, offset long_mode_start
    push eax
    retf
.size _start, . - _start

/* ─── 64-bit entry ─────────────────────────────────────────────── */
.code64
.type long_mode_start, @function
long_mode_start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    /* Recover the bootloader handoff. */
    pop rdi
    pop rsi

    /* Stack remains in low phys during early Rust bringup.
     * Higher-half stack swap happens during Wave 2.
     */
    call _start_rust

1:  hlt
    jmp 1b
.size long_mode_start, . - long_mode_start

/* ─── Boot Data (Physical) ──────────────────────────────────────── */
.section .boot.data, "aw"
.align 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
gdt_end:

.align 8
gdt_ptr:
    .word gdt_end - gdt - 1
    .quad gdt

.align 4096
pml4:
    .skip 4096
pdpt:
    .skip 4096

.align 16
stack_bottom:
    .skip 4096 * 16
stack_top:
