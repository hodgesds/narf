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

    /* ── KASLR: apply the relocation table ──
     *
     * The kernel is linked at a fixed address with `relocation-model=static`,
     * so sliding it means patching every absolute field. `xtask relocs` has
     * already recorded them into `.kaslr_relocs`; this walks that table and
     * adds the slide to each site.
     *
     * Runs HERE, in 32-bit mode before paging, because the recorded offsets
     * are physical: the linker's `AT(ADDR(x) - KERNEL_VIRT_BASE)` makes
     * `virt - KERNEL_VIRT_BASE` exactly the load address, so a table entry is
     * usable as-is with flat 32-bit addressing. It must also run before any
     * patched value is read, and nothing above this point touches one.
     *
     * `ebx` holds the slide, in bytes.
     *
     * Bounds, both of which matter:
     *
     *  - 2 MiB aligned, because the kernel window is mapped with 2 MiB pages.
     *  - Below KASLR_SLIDE_MAX. The module text window starts exactly 1 GiB
     *    above the link base, so a slide approaching 1 GiB would put the image
     *    on top of it; the linker script derives the bound from the image's
     *    real end so it cannot drift as the image grows.
     *
     * Entropy is RDRAND when the CPU has it, TSC otherwise. TSC alone is only
     * boot-time jitter, which is what `kaslr.rs` already documents as
     * acceptable for slot picking.
     */
    mov ebx, 0                                  /* slide, filled in below */

    /* CPUID.1:ECX[30] = RDRAND. CPUID clobbers ebx, so stash it. */
    mov eax, 1
    push ebx
    cpuid
    pop ebx
    test ecx, 0x40000000
    jz .Lslide_tsc

    /* RDRAND, retried a bounded number of times; CF=0 means no data. */
    mov ecx, 32
.Lslide_rdrand:
    rdrand eax
    jc .Lslide_have
    dec ecx
    jnz .Lslide_rdrand

.Lslide_tsc:
    rdtsc                                       /* edx:eax */
    xor eax, edx

.Lslide_have:
    and eax, offset KASLR_SLIDE_MASK            /* clamp to the window  */
    and eax, 0xFFE00000                         /* 2 MiB align          */
    mov ebx, eax

    /* Record it for the Rust conversions (`kaslr::KERNEL_SLIDE`). */
    mov eax, offset __kernel_slide_phys
    mov [eax], ebx
    mov dword ptr [eax + 4], 0

    mov esi, offset __kaslr_relocs_phys
    cmp dword ptr [esi], 0x4B41534C             /* "KASL" */
    jne .Lreloc_done                            /* never patched — skip */
    mov ecx, [esi + 4]                          /* abs64 count   */
    mov edx, [esi + 8]                          /* abs32s count  */
    mov edi, [esi + 12]                         /* pcrel count   */
    add esi, 20                                 /* first entry   */

.Lreloc_64:
    test ecx, ecx
    jz .Lreloc_32s
    mov eax, [esi]
    add [eax], ebx                              /* low half      */
    adc dword ptr [eax + 4], 0                  /* carry, hi = 0 */
    add esi, 4
    dec ecx
    jmp .Lreloc_64

.Lreloc_32s:
    test edx, edx
    jz .Lreloc_pc
    mov eax, [esi]
    add [eax], ebx
    add esi, 4
    dec edx
    jmp .Lreloc_32s

    /* Boot-stub references INTO the kernel half: PC-relative, but only the
     * target moves, so the displacement grows by the same slide. */
.Lreloc_pc:
    test edi, edi
    jz .Lreloc_done
    mov eax, [esi]
    add [eax], ebx
    add esi, 4
    dec edi
    jmp .Lreloc_pc

.Lreloc_done:

    /* ── GOT fixup ──
     *
     * The GOT is not in the relocation table and cannot be: LLD resolves every
     * slot at link time to an absolute kernel-half address, so `--emit-relocs`
     * has no record to emit. Each slot still has to move with the image, and
     * the first indirect call through an unslid one faults on instruction
     * fetch at an address below the window.
     *
     * A slot whose high dword is zero is not a kernel-half pointer (an empty
     * or low entry) and is left alone.
     */
    mov esi, offset __got_phys_start
    mov edi, offset __got_phys_end
.Lgot:
    cmp esi, edi
    jae .Lgot_done
    cmp dword ptr [esi + 4], 0
    je .Lgot_next
    add [esi], ebx
    adc dword ptr [esi + 4], 0
.Lgot_next:
    add esi, 8
    jmp .Lgot
.Lgot_done:

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

    /* ── higher-half kernel window, slid ──
     *
     * Was one 1 GiB page at PDPT[510], which fixes the window at the link
     * base: 1 GiB granularity cannot express a smaller offset. The image now
     * expects to live at `KERNEL_VIRT_BASE + slide`, so the window is built
     * from 2 MiB pages instead, mapping VA (KVB + slide + phys) -> phys for
     * phys in [0, 1 GiB).
     *
     * The window stays entirely inside PDPT[510]. Letting it run the full
     * 1 GiB from `slide` would push its tail into PDPT[511], which is the
     * module text window (`module_text: kernel VA slot 511`) — the boot dies
     * at the MMU handoff with no output when they overlap. So the alias covers
     * phys [0, 1 GiB - slide) instead: the top `slide` bytes lose their
     * kernel-window alias and are reachable through the direct map once that
     * is live, which is where `text_poke::alias_vas` already looks.
     */
    mov edi, offset pd_kernel_lo
    mov ecx, 1024                               /* one 4 KiB table, dwords */
    xor eax, eax
    rep stosd

    xor esi, esi                                /* phys frame index */
.Lkmap:
    mov eax, esi
    shl eax, 21                                 /* phys = i * 2 MiB      */
    mov edx, eax                                /* keep phys            */
    add eax, ebx                                /* + slide = VA offset  */
    shr eax, 21                                 /* -> PD entry index    */
    cmp eax, 512                                /* past PDPT[510]?      */
    jae .Lkmap_done
    shl eax, 3
    mov edi, offset pd_kernel_lo
    add edi, eax
    mov eax, edx
    or  eax, 0x83                               /* P | RW | PS          */
    mov [edi], eax
    mov dword ptr [edi + 4], 0
    inc esi
    cmp esi, 512
    jb .Lkmap
.Lkmap_done:

    lea eax, [pd_kernel_lo]
    or  eax, 0x3
    mov [pdpt + 510 * 8], eax
    mov dword ptr [pdpt + 510 * 8 + 4], 0

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
/*
 * `rbx` still holds the KASLR slide. Nothing between its computation and here
 * writes ebx: the apply pass reads it as the delta, the page-table build uses
 * eax/ecx/edx/esi/edi, and the CR4/EFER/CR0 sequence clobbers only eax/ecx/edx
 * (`cpuid` does clobber ebx, which is why the one above brackets it with
 * push/pop).
 */
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
    add rax, rbx                                /* + KASLR slide    */
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
/* 2 MiB leaves for the slid kernel window. One table: the window is clamped
 * to PDPT[510] so it cannot collide with the module text window at
 * PDPT[511]. */
pd_kernel_lo:
    .skip 4096

.align 16
stack_bottom:
    .skip 4096 * 16
stack_top:
