/*
 * NARF x86_64 boot stub.
 *
 * Multiboot2 entry → long mode → _start_rust(magic: u64, payload: u64).
 *
 * On entry from the bootloader:
 *   - 32-bit protected mode, paging off.
 *   - EAX = 0x36d76289 (MULTIBOOT2_BOOTLOADER_MAGIC).
 *   - EBX = physical address of the multiboot2 info structure.
 *   - CS = 32-bit code segment; DS/ES/SS = 32-bit data (bootloader's GDT).
 *   - IF = 0 (interrupts disabled).
 *
 * We:
 *   1. Set up a 64 KiB stack in .bss.
 *   2. Build identity page tables covering the first 1 GiB with a single
 *      1-GiB huge page (PML4[0] → PDPT[0] with PS=1).
 *   3. Enable PAE, set IA32_EFER.LME, enable paging — this transitions to
 *      IA-32e compatibility mode.
 *   4. Load a 64-bit GDT and far-jump into 64-bit code.
 *   5. Clear data selectors and call _start_rust with magic in RDI and
 *      info-pointer in RSI.
 *
 * Stage-1 simplifications acknowledged:
 *   - Low-half-only (phys == virt == 0x0010_0000+). High-half relocation
 *     lands with memory/ at Wave 2.
 *   - No CPUID check for long-mode / PAE — QEMU q35 with -cpu max supplies
 *     both unconditionally. Real-hardware boot will grow the check in the
 *     Stage-2 feature-detection pass.
 *   - No PKS probe — Stage-1 has no domain switch, so the MSR is never used.
 */

/* Intel syntax is the default in rustc's integrated assembler, so no
 * explicit syntax directive is needed (and emitting one earns a
 * bad_asm_style warning).
 */

/* ─── PVH ELF Note ──────────────────────────────────────────────────
 *
 * QEMU's `-kernel` loader for x86_64 rejects Multiboot v1 (32-bit only)
 * and doesn't speak v2. The third native path is the Xen PVH entry
 * protocol: an ELF note names a 32-bit entry address, and QEMU jumps
 * there in 32-bit protected mode with paging off. That state matches
 * what the rest of this boot stub expects.
 *
 * On entry:
 *   - 32-bit protected mode, paging off, IF=0.
 *   - EBX = physical address of a `hvm_start_info` struct (we ignore it
 *     in Stage 1; memory-map parsing from it lands with the Limine
 *     integration in the boot/ spec §5).
 *   - EAX is unspecified — do NOT rely on it.
 *
 * Limine/Multiboot2 is the design-time target per boot/ spec §5; PVH is
 * the Stage-1 practicality because it's the only ELF64 boot path
 * `qemu-system-x86_64 -kernel` supports out of the box.
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
    cli                                         /* belt & braces */

    /* Stack: 64 KiB in .bss. */
    lea esp, [stack_top]

    /* Stash the bootloader handoff. The SysV AMD64 ABI wants magic in RDI
     * and info-ptr in RSI, so we push "payload high / payload low /
     * magic high / magic low" — after the transition, `pop rdi` then
     * `pop rsi` pulls them in order.
     */
    push 0                                      /* upper half of payload */
    push ebx                                    /* lower half of payload */
    push 0                                      /* upper half of magic   */
    push eax                                    /* lower half of magic   */

    /* ── identity-map the first 1 GiB ──
     * PML4[0] → PDPT  (P | RW)
     */
    lea eax, [pdpt]
    or  eax, 0x3
    mov [pml4], eax
    mov dword ptr [pml4 + 4], 0

    /* PDPT[0] = 0 | (P | RW | PS)      — 1-GiB huge page at phys 0 */
    mov dword ptr [pdpt], 0x83
    mov dword ptr [pdpt + 4], 0

    /* CR3 = &PML4 */
    lea eax, [pml4]
    mov cr3, eax

    /* CR4.PAE = 1 (bit 5) */
    mov eax, cr4
    or  eax, 0x20
    mov cr4, eax

    /* IA32_EFER.LME = 1 (bit 8) — MSR 0xC0000080 */
    mov ecx, 0xC0000080
    rdmsr
    or  eax, 0x100
    wrmsr

    /* CR0.PG = 1 (bit 31) — paging on, enters compat mode */
    mov eax, cr0
    or  eax, 0x80000000
    mov cr0, eax

    /* Load our GDT and far-jump into 64-bit code. 0x08 selects the
     * 64-bit code descriptor at offset 8 in the GDT.
     */
    lgdt [gdt_ptr]
    ljmp 0x08, offset long_mode_start
.size _start, . - _start

/* ─── 64-bit entry ─────────────────────────────────────────────── */
.code64
.type long_mode_start, @function
long_mode_start:
    /* Data selectors are effectively ignored in long mode but the
     * architecture still writes back loads, so point them at the null
     * descriptor to make any accidental memory reference trap.
     */
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    /* Recover the bootloader handoff. We pushed (in 32-bit order):
     *   upper_payload, lower_payload, upper_magic, lower_magic
     * so RSP now points at lower_magic. `pop rdi` reads the 8 bytes
     * (magic), `pop rsi` reads the next 8 bytes (payload).
     */
    pop rdi
    pop rsi

    call _start_rust

    /* If Rust returns (it shouldn't — `_start_rust(...) -> !`), halt. */
1:  hlt
    jmp 1b
.size long_mode_start, . - long_mode_start

/* ─── GDT ───────────────────────────────────────────────────────── */
.section .rodata
.align 8
gdt:
    .quad 0                                 /* 0x00: null descriptor   */
    .quad 0x00af9a000000ffff                /* 0x08: 64-bit kernel code
                                             * L=1, P=1, DPL=0, S=1,
                                             * type=exec/read */
gdt_end:

.align 8
gdt_ptr:
    .word gdt_end - gdt - 1
    .quad gdt                               /* 10-byte pseudo-descriptor
                                             * for LGDT in 64-bit mode;
                                             * LGDT in 32-bit mode reads
                                             * the same base as a dword,
                                             * which is correct because
                                             * our load address fits in
                                             * 32 bits. */

/* ─── page tables and stack (uninitialised .bss) ─────────────────── */
.section .bss
.align 4096
pml4:
    .skip 4096

.align 4096
pdpt:
    .skip 4096

.align 16
stack_bottom:
    .skip 4096 * 16                         /* 64 KiB boot stack       */
stack_top:
