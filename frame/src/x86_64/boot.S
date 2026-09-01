/*
 * NARF x86_64 boot stub.
 *
 * Two entry protocols share `_start`:
 *
 *   1. Xen PVH (`.note.Xen` ELFNOTE 18) — QEMU `-kernel` direct boot.
 *      Loader sets EBX = phys(`hvm_start_info`); EAX is undefined, so
 *      the Rust side discriminates by reading the `xEn3` magic from
 *      the payload itself.
 *   2. Multiboot2 (`.multiboot2_header` in the first 32 KiB of the
 *      file) — Limine, GRUB, and any other multiboot2-aware loader.
 *      Loader sets EAX = 0x36d76289 and EBX = phys(mbi struct).
 *
 * The code in `_start` doesn't need to know which protocol it was
 * launched under: it just stashes EAX + EBX in (RDI, RSI) for
 * `_start_rust`, which routes on the magic.
 */

/* ─── Multiboot2 header ────────────────────────────────────────────
 *
 * Spec: <https://www.gnu.org/software/grub/manual/multiboot2/>
 * §3.1 — header layout. Must be 8-byte aligned and in the first
 * 32 KiB of the file. Placed at the very start of the `.boot`
 * section so the file offset is small.
 */
.section .multiboot2_header, "a"
.align 8
mb2_header_start:
    .long 0xe85250d6                                /* magic       */
    .long 0                                          /* arch i386   */
    .long mb2_header_end - mb2_header_start          /* hdr length  */
    .long -(0xe85250d6 + 0 + (mb2_header_end - mb2_header_start)) /* checksum */

    /* Framebuffer-request tag — multiboot2 §3.1.10 (type 5). Asks
     * the bootloader to set up a graphical RGB framebuffer instead
     * of leaving us in EGA text mode; without this, Limine on real
     * hardware boots the kernel with no framebuffer info tag and
     * we get a UART-only console. flags=1 (optional) so a loader
     * that can't honour the request still boots us — the kernel
     * already handles the no-FB case gracefully (serial console).
     * Width/height/depth = 0 = "let the loader pick the preferred
     * mode" (1024x768x32 on most QEMU/OVMF combos; native panel
     * resolution on real hardware via GOP). */
    .align 8
    .short 5                                         /* type = 5    */
    .short 1                                         /* flags = optional */
    .long 20                                         /* size = 20   */
    .long 0                                          /* width       */
    .long 0                                          /* height      */
    .long 0                                          /* depth       */

    /* End tag — type 0, flags 0, size 8. */
    .align 8
    .short 0
    .short 0
    .long 8
mb2_header_end:

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

    /* ── identity-map the first 4 GiB + higher-half mapping ──
     *
     * 4-GiB identity coverage matters for real-HW boot: UEFI GOP
     * framebuffers on laptops often sit above 1 GiB phys (GPU
     * BAR region, typically 0x80000000+). The kernel's
     * post-MMU-init code paths assume the early identity map
     * covers anything the bootloader's info structures point at;
     * truncating to 1 GiB silently faults on the first FB write.
     * Four PDPT entries with PS=1 cover 0..4 GiB at zero memory
     * cost (PDPT is already a full page).
     */
    lea eax, [pdpt]
    or  eax, 0x3                                /* P | RW */

    mov [pml4], eax                             /* PML4[0] */
    mov [pml4 + 511 * 8], eax                   /* PML4[511] */

    /* PDPT[0..3] = 0..3 GiB | (P | RW | PS) — identity 0..4 GiB.
     * PDPT[510]  = 0 | (P | RW | PS)         — higher-half = phys 0..1 GiB. */
    mov dword ptr [pdpt + 0 * 8],     0x00000083  /* 0..1 GiB */
    mov dword ptr [pdpt + 1 * 8],     0x40000083  /* 1..2 GiB */
    mov dword ptr [pdpt + 2 * 8],     0x80000083  /* 2..3 GiB */
    mov dword ptr [pdpt + 3 * 8],     0xC0000083  /* 3..4 GiB */
    mov dword ptr [pdpt + 510 * 8],   0x00000083  /* higher-half */

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

    /* Move the stack to its higher-half alias before entering Rust.
     *
     * `stack_top` is a .boot.data address, i.e. low physical. That was
     * fine while every address space carried the low identity map, but
     * PML4[0] is user space now: a kernel task scheduled onto a user CR3
     * would find its own stack unmapped and take a #PF on the push, then
     * #DF on the fault handler's own push.
     *
     * The alias is already live -- boot.S maps PML4[511] -> pdpt and
     * pdpt[510] -> phys 0..1 GiB, and `init_mmu` keeps that same window
     * through `pd_hi_kernel`, so `phys + KERNEL_VIRT_BASE` addresses the
     * identical bytes both before and after the MMU handoff.
     *
     * Done HERE, at the one point where the stack is empty: the handoff
     * pops are complete and Rust has not run, so no saved frame pointer
     * and no pointer-to-stack-local exists yet to be left pointing at the
     * low alias. Every push from the `call` below lands high.
     */
    movabs rax, 0xFFFFFFFF80000000              /* KERNEL_VIRT_BASE */
    add rsp, rax

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
