/*
 * AP trampoline: 16-bit real mode → 32-bit protected → 64-bit long.
 *
 * The BSP copies this blob to TRAMPOLINE_PHYS = 0x8000 at boot, patches
 * a few parameters into the parameter block, then sends INIT-SIPI-SIPI
 * with vector-page = 0x08 (CS:IP = 0x800:0x0000 → linear 0x8000).
 *
 * Reaches the same address space the BSP set up: CR3 is patched in
 * by Rust before SIPI, and the BSP's identity mapping of the first
 * 1 GiB covers both the trampoline and the kernel high half.
 *
 * Memory access pattern: LLVM IAS rejects symbol arithmetic in
 * memory operands (`[sym - sym]`), so all in-trampoline data accesses
 * route through register-indirect form. `.equ`-defined offset
 * constants need the `offset` keyword to be loaded as immediates
 * rather than treated as memory addresses.
 *
 * The 32-bit GDT base is patched by Rust to TRAMPOLINE_PHYS+offset.
 * The kernel GDT base passed in `ap_param_gdt_base` is the *physical*
 * address (virt − KERNEL_VIRT_BASE), so the lgdt-then-far-jump
 * sequence works after CR0.PG=1 — the new PML4's identity map covers
 * the kernel image's phys range.
 */

.section .text.ap_trampoline, "ax"
.global _ap_trampoline_start
.global _ap_trampoline_end
.global ap_param_cr3
.global ap_param_gdt_limit
.global ap_param_gdt_base
.global ap_param_stacks
.global ap_param_rust_entry
.global ap_param_gdt32_base

.equ TRAMPOLINE_PHYS, 0x8000

/* ─── 16-bit real-mode entry ─────────────────────────────────────── */
.code16
_ap_trampoline_start:
    cli
    cld

    /* CS = 0x800 (post-SIPI). Mirror to DS/ES/SS so absolute symbol
     * references resolve correctly in real mode. */
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x0FF0          /* tiny stack inside trampoline page */

    /* Load 32-bit GDT — the GDTR pseudo-descriptor lives at offset
     * GDT32_PTR_OFF inside the trampoline page. With DS=CS=0x800,
     * absolute offset = TRAMPOLINE_PHYS + GDT32_PTR_OFF; the lgdt
     * memory operand resolves via DS:offset. The 0x66 operand-size
     * override forces LGDT m16&32 (full 32-bit base) — without it,
     * real-mode LGDT defaults to m16&24 and silently zeros the high
     * byte of base. */
    mov bx, offset GDT32_PTR_OFF
    .byte 0x66
    lgdt [bx]

    /* CR0.PE = 1 → protected mode. */
    mov eax, cr0
    or  eax, 1
    mov cr0, eax

    /* Far jump to 32-bit code segment. Encode `ljmp imm32, imm16`
     * manually because LLVM IAS rejects two-symbol arithmetic in
     * the offset field of an `ljmp` mnemonic. */
    .byte 0x66, 0xEA            /* operand-size override + ljmp */
    .long _ap_protected_start - _ap_trampoline_start + TRAMPOLINE_PHYS
    .word 0x08

/* ─── 32-bit protected mode ──────────────────────────────────────── */
.code32
_ap_protected_start:
    /* Reload data segment with the 32-bit data selector (0x10). */
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    /* Load CR3 = patched PML4 phys. */
    mov ebx, offset AP_PARAM_CR3_OFF
    mov eax, [ebx + TRAMPOLINE_PHYS]
    mov cr3, eax

    /* CR4.PAE = 1 (bit 5). */
    mov eax, cr4
    or  eax, 0x20
    mov cr4, eax

    /* IA32_EFER.LME = 1 (bit 8) and IA32_EFER.NXE = 1 (bit 11).
     *
     * NXE must be set HERE, before CR0.PG, not in `_ap_start_rust`.
     * The BSP's PML4 — which this AP is about to load — marks almost
     * every leaf NO_EXEC (PTE bit 63) so that no kernel data has an
     * executable alias. With NXE clear, bit 63 is a RESERVED bit, and
     * the very first instruction fetch after `mov cr0` takes a
     * reserved-bit #PF with no IDT loaded: a triple fault at a point
     * where the AP has no console. `enable_nxe()` in `_ap_start_rust`
     * is far too late — the AP has to survive the walk to get there.
     *
     * Unconditional because the BSP already hard-failed the boot if
     * CPUID did not report NX (`bare_main.rs`, "EFER.NXE not enabled"),
     * so by the time any AP runs, NX is known present. */
    mov ecx, 0xC0000080
    rdmsr
    or  eax, 0x900
    wrmsr

    /* CR0.PG = 1 (bit 31). PE is already set. */
    mov eax, cr0
    or  eax, 0x80000000
    mov cr0, eax

    /* Long-mode-compat now active. Load the kernel GDT — the param
     * block holds a 6-byte m16&32 descriptor (limit + 32-bit phys
     * base). */
    mov ebx, offset AP_PARAM_GDT_LIMIT_OFF
    lgdt [ebx + TRAMPOLINE_PHYS]

    /* Far jump to selector 0x08 (kernel 64-bit code). LLVM IAS rejects
     * two-symbol arithmetic in the `ljmp imm32, imm16` operand, so we
     * encode the instruction by hand. */
    .byte 0xEA                  /* ljmp ptr16:32 — 32-bit operand size */
    .long _ap_long_mode_start - _ap_trampoline_start + TRAMPOLINE_PHYS
    .word 0x08

/* ─── 64-bit long mode ───────────────────────────────────────────── */
.code64
_ap_long_mode_start:
    /* Zero data-segment selectors per long-mode convention. */
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    /* Read this AP's APIC ID (CPUID leaf 1 EBX[31:24]) — used as the
     * logical CPU index. QEMU `-smp N` assigns APIC ids 0..N-1, so
     * APIC id == logical id. */
    mov eax, 1
    cpuid
    shr ebx, 24
    movzx rdi, bl                       /* rdi = logical_id */

    /* rsp = AP_STACKS[logical_id]. RIP-relative load: the relative
     * offset between the instruction and ap_param_stacks is preserved
     * when the trampoline is copied to TRAMPOLINE_PHYS. */
    mov rsi, qword ptr [rip + ap_param_stacks]
    mov rsp, qword ptr [rsi + rdi * 8]

    /* Tail-call into Rust: rdi already holds logical_id. */
    mov rax, qword ptr [rip + ap_param_rust_entry]
    jmp rax

    /* Unreachable — rust entry is `-> !`. */
1:  hlt
    jmp 1b

/* ─── Parameter block ────────────────────────────────────────────── */
.balign 8
ap_param_cr3:
    .quad 0                         /* CR3 = PML4 phys */

ap_param_gdt_limit:
    .word 0                         /* limit (2 bytes) */
ap_param_gdt_base:
    .long 0                         /* phys base low 32 bits (lgdt m16&32) */

.balign 8
ap_param_stacks:
    .quad 0                         /* absolute virt &AP_STACKS[0] */

ap_param_rust_entry:
    .quad 0                         /* absolute virt &_ap_start_rust */

/* ─── 32-bit GDT (used during 16→32 transition only) ─────────────── */
.balign 8
gdt32_start:
    .quad 0                                 /* null */
    .quad 0x00CF9A000000FFFF                /* 32-bit code: G=1 D=1 type=0xA */
    .quad 0x00CF92000000FFFF                /* 32-bit data: type=0x2 */
gdt32_end:

.balign 4
gdt32_ptr:
    .word gdt32_end - gdt32_start - 1
ap_param_gdt32_base:
    .long 0                                 /* base, patched by Rust */

_ap_trampoline_end:
.size _ap_trampoline_start, _ap_trampoline_end - _ap_trampoline_start

/* ─── Pre-computed offsets (intra-section, foldable to integers) ── */
.equ GDT32_PTR_OFF,           gdt32_ptr           - _ap_trampoline_start
.equ AP_PARAM_CR3_OFF,        ap_param_cr3        - _ap_trampoline_start
.equ AP_PARAM_GDT_LIMIT_OFF,  ap_param_gdt_limit  - _ap_trampoline_start
