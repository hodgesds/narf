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
    /* ── Physical relocation ────────────────────────────────────────────
     *
     * Copy the image to a randomly chosen physical address and continue
     * executing from the copy. The VA slide below randomizes where the image
     * APPEARS; this randomizes where it IS, which the slide cannot do — the
     * loader chooses the physical address.
     *
     * ebp holds the delta for the rest of the stub. Every physical address the
     * stub uses afterwards is a link-time one, so each gets ebp added: the
     * relocation table, the GOT bounds, the page tables, the far return into
     * long mode, and the two values recorded for Rust. Miss one and it reads or
     * writes the stale copy, which still exists and still looks valid.
     *
     * `esp` is the deliberate exception. It stays link-time-physical because
     * `long_mode_start` turns it into a VA with `add rsp, KERNEL_VIRT_BASE +
     * slide`, and the window maps that VA to `offset + delta` — so the delta is
     * already accounted for. Adding ebp here would count it twice.
     *
     * Target selection, in `.Lphys_pick` below, must satisfy:
     *
     *  - inside RAM the loader marked usable (type 1), entirely within ONE
     *    entry, so we never straddle a hole or a reserved range;
     *  - at or above `__kernel_end`, which makes the delta positive and larger
     *    than the image, so the forward `rep movsd` cannot overwrite its own
     *    source (and keeps the delta a 32-bit unsigned value, which is what
     *    `IMAGE_PHYS_DELTA` and every `add <reg>, ebp` below assume);
     *  - below 4 GiB, which the stub's identity map covers (PDPT[0..3]);
     *  - clear of everything the bootloader placed: the info struct, the memory
     *    map array, the module list, every module (the initramfs is one —
     *    clobbering it destroys the rootfs), and the cmdline strings.
     *
     * Only the Xen PVH handoff is parsed. Under multiboot2 the image stays
     * where the loader put it: the tag walk is a different format, and nothing
     * in this tree can boot it to test the result. Relocation being off is the
     * safe answer for an unrecognized handoff, not a silent guess.
     */
    mov ebp, 0                                  /* physical delta; 0 = none */

    /* A pinned delta skips selection entirely, for reproducing a specific
     * layout. Deliberately NOT validated against the memory map, mirroring
     * KASLR_SLIDE_FIXED: a developer override that silently declined to apply
     * would be worse to debug than one that faults. */
    mov eax, offset KASLR_PHYS_FIXED
    test eax, eax
    jnz .Lphys_have

    mov eax, offset KASLR_PHYS_ENABLE
    test eax, eax
    jz .Lphys_done

    call .Lphys_pick                            /* eax = delta, 0 on failure */
    test eax, eax
    jz .Lphys_done

.Lphys_have:
    mov ebp, eax

    mov esi, offset __kernel_start
    mov edi, esi
    add edi, ebp
    mov ecx, offset __kernel_end
    sub ecx, esi
    add ecx, 3
    shr ecx, 2                                  /* bytes -> dwords */
    cld
    rep movsd

    /* Continue in the copy. Everything after this label runs at +ebp. */
    mov eax, offset .Lphys_done
    add eax, ebp
    jmp eax
.Lphys_done:

    mov ebx, 0                                  /* slide, filled in below */

    /* A pinned slide (KASLR_SLIDE_FIXED != 0) skips entropy entirely. It
     * still falls through the mask + align below, so it cannot escape the
     * window. See the linker script for why this exists. */
    mov eax, offset KASLR_SLIDE_FIXED
    test eax, eax
    jnz .Lslide_have

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
    add eax, ebp                                /* the copy's, not the original's */
    mov [eax], ebx
    mov dword ptr [eax + 4], 0

    /* Record the physical delta for `kaslr::image_virt_to_phys` and
     * `image_phys_bounds`. The frame allocator reserves those bounds, so a
     * missing delta leaves the running image unreserved. */
    mov eax, offset __image_phys_delta_phys
    add eax, ebp
    mov [eax], ebp
    mov dword ptr [eax + 4], 0

    mov esi, offset __kaslr_relocs_phys
    add esi, ebp
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
    add eax, ebp                                /* site is link-time phys */
    add [eax], ebx                              /* low half      */
    adc dword ptr [eax + 4], 0                  /* carry, hi = 0 */
    add esi, 4
    dec ecx
    jmp .Lreloc_64

.Lreloc_32s:
    test edx, edx
    jz .Lreloc_pc
    mov eax, [esi]
    add eax, ebp
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
    add eax, ebp
    /* += slide - delta, not just += slide.
     *
     * A PC-relative field is slide-invariant only when its source and its
     * target move together, which is why these sites need patching at all: the
     * target moves with the slide and the boot stub does not. Physical
     * relocation breaks the other half of that — the SOURCE moves too, by
     * `delta`, because the instruction itself was copied.
     *
     *   link time  disp  = (KVB + off) - link_phys
     *   runtime    want    (KVB + slide + off) - (link_phys + delta)
     *                    = disp + slide - delta
     *
     * Adding only the slide leaves the call `delta` short, which lands on the
     * UNSLID `_start_rust` — mapped by nothing, so the first call into Rust
     * takes a not-present instruction fetch and triple-faults with no output. */
    add [eax], ebx
    sub [eax], ebp
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
    add esi, ebp
    mov edi, offset __got_phys_end
    add edi, ebp
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
    /* Page tables are inside the copied image, so their physical addresses
     * moved with it. `esi`/`edi` are in use below, so `ecx` carries the two
     * table addresses here. */
    lea eax, [pdpt]
    add eax, ebp
    or  eax, 0x3                                /* P | RW */

    mov ecx, offset pml4
    add ecx, ebp
    mov [ecx], eax                              /* PML4[0] */
    mov [ecx + 511 * 8], eax                    /* PML4[511] */

    /* PDPT[0..3] = 0..3 GiB | (P | RW | PS) — identity 0..4 GiB.
     * PDPT[510]  = 0 | (P | RW | PS)         — higher-half = phys 0..1 GiB. */
    mov ecx, offset pdpt
    add ecx, ebp
    mov dword ptr [ecx + 0 * 8],      0x00000083  /* 0..1 GiB */
    mov dword ptr [ecx + 1 * 8],      0x40000083  /* 1..2 GiB */
    mov dword ptr [ecx + 2 * 8],      0x80000083  /* 2..3 GiB */
    mov dword ptr [ecx + 3 * 8],      0xC0000083  /* 3..4 GiB */

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
    add edi, ebp
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
    add edi, ebp
    add edi, eax
    mov eax, edx
    add eax, ebp                                /* the image's new phys  */
    or  eax, 0x83                               /* P | RW | PS          */
    mov [edi], eax
    mov dword ptr [edi + 4], 0
    inc esi
    cmp esi, 512
    jb .Lkmap
.Lkmap_done:

    lea eax, [pd_kernel_lo]
    add eax, ebp
    or  eax, 0x3
    mov ecx, offset pdpt
    add ecx, ebp
    mov [ecx + 510 * 8], eax
    mov dword ptr [ecx + 510 * 8 + 4], 0

    /* CR3 = &PML4, in the copy */
    mov eax, offset pml4
    add eax, ebp
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
    /* Both of these name link-time addresses, so both need the delta.
     *
     * `gdt_ptr`'s base is `.quad gdt`, a low-half address the relocation
     * classifier correctly ignores (it does not move with the slide), so the
     * stub has to fix it itself. Leaving it stale would load GDTR with a
     * pointer into the ORIGINAL image, which is no longer inside the reserved
     * physical bounds — so the buddy allocator could hand that memory out from
     * under a live GDT.
     *
     * The far return is the one that must not be missed: landing on the
     * original `long_mode_start` means `call _start_rust` below executes from
     * the original image, whose pcrel displacement was never patched (the
     * patch went to the copy), so it jumps to the UNSLID `_start_rust`. */
    mov eax, offset gdt_ptr
    add eax, ebp
    add dword ptr [eax + 2], ebp                /* base -> the copy's GDT */
    lgdt [eax]

    push 0x08
    mov eax, offset long_mode_start
    add eax, ebp                                /* continue in the copy */
    push eax
    retf

/* ── Physical relocation target selection (32-bit, pre-copy) ─────────
 *
 * Runs before the copy, so every address here is a link-time one and none of
 * them needs the delta.
 *
 * In:  ebx = bootloader info pointer, still live from `_start` (nothing above
 *      has clobbered it; the handoff copy on the stack is for `_start_rust`).
 * Out: eax = chosen delta, or 0 if no safe target was found.
 * Clobbers eax, ecx, edx, esi, edi. Preserves ebx and ebp.
 *
 * Rejection sampling rather than computing a safe floor: the ranges to avoid
 * are not sorted and not contiguous, so "pick, then verify" is both shorter and
 * easier to argue about than "find the lowest gap big enough". 64 attempts is
 * far more than enough when the usable region is orders of magnitude larger
 * than the image, and failing closed (delta 0) is always safe.
 */
.Lphys_pick:
    /* Any failure below unwinds to here from an arbitrary call depth, so park
     * esp rather than balancing each path by hand. */
    mov [reloc_esp], esp

    cmp dword ptr [ebx], 0x336EC578             /* "xEn3" — PVH handoff? */
    jne .Lphys_pick_fail

    /* Every field consumed here has to sit below 4 GiB, because this code is
     * 32-bit and the target must land inside the identity map anyway. A
     * non-zero high dword means an address this routine cannot reason about,
     * so decline rather than truncate it. */
    cmp dword ptr [ebx + 0x2C], 0               /* memmap_paddr high */
    jne .Lphys_pick_fail
    mov eax, [ebx + 0x28]
    mov [reloc_mmap], eax
    mov eax, [ebx + 0x30]                       /* memmap_entries */
    test eax, eax
    jz .Lphys_pick_fail
    cmp eax, 1024
    ja .Lphys_pick_fail                         /* implausible; bail */
    mov [reloc_nent], eax

    /* The image's span, rounded up to the 2 MiB placement granularity. The
     * copy itself still moves the exact byte count. */
    mov eax, offset __kernel_end
    sub eax, offset __kernel_start
    add eax, 0x1FFFFF
    and eax, 0xFFE00000
    mov [reloc_size], eax

    /* ── Collect the ranges the target must not touch ── */
    xor edi, edi                                /* avoid-list count */

    mov eax, ebx                                /* the info struct itself */
    mov ecx, 0x38
    call .Lphys_add_avoid

    mov eax, [reloc_nent]                       /* the memory map array */
    imul eax, eax, 24
    mov ecx, eax
    mov eax, [reloc_mmap]
    call .Lphys_add_avoid

    /* Cmdline strings have no length in the handoff, so guard a fixed span.
     * Kernel cmdlines are a few hundred bytes; 4 KiB is slack, and being
     * conservative here only costs candidate positions. */
    cmp dword ptr [ebx + 0x1C], 0               /* cmdline_paddr high */
    jne .Lphys_pick_fail
    mov eax, [ebx + 0x18]
    test eax, eax
    jz .Lphys_no_cmdline
    mov ecx, 4096
    call .Lphys_add_avoid
.Lphys_no_cmdline:

    mov eax, [ebx + 0x0C]                       /* nr_modules */
    test eax, eax
    jz .Lphys_mods_done
    cmp eax, 64
    ja .Lphys_pick_fail
    cmp dword ptr [ebx + 0x14], 0               /* modlist_paddr high */
    jne .Lphys_pick_fail
    mov esi, [ebx + 0x10]

    mov ecx, eax                                /* the modlist array itself */
    shl ecx, 5                                  /* 32 bytes per entry */
    mov eax, esi
    call .Lphys_add_avoid

    mov edx, [ebx + 0x0C]                       /* per-module counter */
.Lphys_mod_loop:
    test edx, edx
    jz .Lphys_mods_done
    cmp dword ptr [esi + 0x04], 0               /* paddr high */
    jne .Lphys_pick_fail
    cmp dword ptr [esi + 0x0C], 0               /* size high  */
    jne .Lphys_pick_fail
    /* The initramfs arrives as a module. Overlapping it would destroy the
     * rootfs silently — the copy would succeed and the mount would not. */
    mov eax, [esi]
    mov ecx, [esi + 0x08]
    call .Lphys_add_avoid
    cmp dword ptr [esi + 0x14], 0               /* module cmdline high */
    jne .Lphys_pick_fail
    mov eax, [esi + 0x10]
    test eax, eax
    jz .Lphys_mod_next
    mov ecx, 4096
    call .Lphys_add_avoid
.Lphys_mod_next:
    add esi, 32
    dec edx
    jmp .Lphys_mod_loop
.Lphys_mods_done:
    mov [reloc_navoid], edi

    /* At or above the image's end: makes the delta positive and no smaller than
     * the image, so the forward copy cannot eat its own source. */
    mov eax, offset __kernel_end
    add eax, 0x1FFFFF
    and eax, 0xFFE00000
    mov [reloc_floor], eax

    mov edi, 64                                 /* attempts */
.Lphys_try:
    test edi, edi
    jz .Lphys_pick_fail
    dec edi

    call .Lphys_rand
    and eax, 0xFFE00000                         /* 2 MiB aligned, below 4 GiB */
    cmp eax, [reloc_floor]
    jb .Lphys_try
    mov ecx, eax
    add ecx, [reloc_size]
    jc .Lphys_try                               /* would pass 4 GiB */
    mov [reloc_target], eax

    call .Lphys_in_ram
    test eax, eax
    jz .Lphys_try

    call .Lphys_clear
    test eax, eax
    jz .Lphys_try

    mov eax, [reloc_target]
    sub eax, offset __kernel_start
    ret

.Lphys_pick_fail:
    mov esp, [reloc_esp]
    xor eax, eax
    ret

/* eax = base, ecx = length. Appends to the avoid list. Preserves every
 * register except edi (the running count). */
.Lphys_add_avoid:
    test ecx, ecx
    jz .Lphys_add_ret                           /* empty range: nothing to do */
    cmp edi, 32
    jae .Lphys_pick_fail                        /* list full: fail closed */
    push edx
    mov edx, edi
    shl edx, 3
    add edx, offset reloc_avoid
    mov [edx], eax
    mov [edx + 4], ecx
    pop edx
    inc edi
.Lphys_add_ret:
    ret

/* eax = 1 if the candidate lies entirely inside ONE usable-RAM entry.
 * Straddling two adjacent entries is rejected: they may be adjacent in the
 * table and not in reality. */
.Lphys_in_ram:
    mov esi, [reloc_mmap]
    mov ecx, [reloc_nent]
.Lphys_ram_loop:
    test ecx, ecx
    jz .Lphys_ram_no
    cmp dword ptr [esi + 0x10], 1               /* type 1 = usable RAM */
    jne .Lphys_ram_next
    cmp dword ptr [esi + 0x04], 0               /* addr high */
    jne .Lphys_ram_next
    mov eax, [esi]
    cmp [reloc_target], eax
    jb .Lphys_ram_next                          /* starts below this entry */
    cmp dword ptr [esi + 0x0C], 0               /* size high */
    jne .Lphys_ram_yes                          /* entry runs past 4 GiB */
    add eax, [esi + 0x08]
    jc .Lphys_ram_yes                           /* ends at or past 4 GiB */
    mov edx, [reloc_target]
    add edx, [reloc_size]
    cmp eax, edx
    jb .Lphys_ram_next                          /* entry ends too early */
.Lphys_ram_yes:
    mov eax, 1
    ret
.Lphys_ram_next:
    add esi, 24
    dec ecx
    jmp .Lphys_ram_loop
.Lphys_ram_no:
    xor eax, eax
    ret

/* eax = 1 if the candidate overlaps nothing on the avoid list.
 * Two ranges are disjoint iff one ends at or before the other begins. */
.Lphys_clear:
    mov esi, offset reloc_avoid
    mov ecx, [reloc_navoid]
.Lphys_clear_loop:
    test ecx, ecx
    jz .Lphys_clear_ok
    mov eax, [esi]                              /* base */
    mov edx, [reloc_target]
    add edx, [reloc_size]
    cmp eax, edx
    jae .Lphys_clear_next                       /* base >= our end */
    mov edx, eax
    add edx, [esi + 4]
    jc .Lphys_clear_bad                         /* range wraps: assume overlap */
    cmp [reloc_target], edx
    jae .Lphys_clear_next                       /* we start at or after its end */
.Lphys_clear_bad:
    xor eax, eax
    ret
.Lphys_clear_next:
    add esi, 8
    dec ecx
    jmp .Lphys_clear_loop
.Lphys_clear_ok:
    mov eax, 1
    ret

/* eax = 32 random bits. RDRAND when the CPU has it, TSC otherwise — the same
 * entropy the slide uses, and the same caveat applies: TSC alone is boot-time
 * jitter. Preserves ebx, which still holds the info pointer. */
.Lphys_rand:
    push ebx
    mov eax, 1
    cpuid
    test ecx, 0x40000000
    pop ebx                                     /* pop does not touch flags */
    jz .Lphys_rand_tsc
    mov ecx, 32
.Lphys_rand_rd:
    rdrand eax
    jc .Lphys_rand_ret
    dec ecx
    jnz .Lphys_rand_rd
.Lphys_rand_tsc:
    rdtsc
    xor eax, edx
.Lphys_rand_ret:
    ret

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

    /* Absolute, not `call _start_rust`. rax already holds the slid image base,
     * so adding the entry's link-time offset gives its live VA.
     *
     * A `call rel32` reaches only +/-2 GiB from the instruction. The stub runs
     * at the image's PHYSICAL address and the target is in the kernel half, so
     * that call reached only while the physical target sat below the slide —
     * coupling two supposedly independent randomizations. Above it the
     * displacement overflowed and the truncated rel32 jumped into unmapped
     * memory, hanging the boot for one slide/delta pair and not the next. This
     * also removes the last cross-half pcrel relocation. */
    mov ecx, offset __start_rust_off
    add rax, rcx
    call rax

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
/* Scratch for `.Lphys_pick`, used before the image is copied and dead after.
 * In `.boot.data` so it is writable in 32-bit mode with paging off. */
.align 4
reloc_esp:      .long 0
reloc_mmap:     .long 0
reloc_nent:     .long 0
reloc_size:     .long 0
reloc_floor:    .long 0
reloc_target:   .long 0
reloc_navoid:   .long 0
reloc_avoid:    .fill 32, 8, 0                  /* 32 x (base, length) */

/* 16-byte aligned, explicitly.
 *
 * Nothing here used to say so: the stack happened to be aligned because of what
 * preceded it. Adding the `reloc_*` scratch above shifted it by 284 bytes — 4
 * mod 8 — and every rsp derived from `stack_top` became misaligned. The
 * scheduler's context guard caught it as "refusing kernel_switch into corrupt
 * context" with an rsp that was canonical but 4 mod 8, which reads like a
 * scheduler race rather than a linker layout problem.
 *
 * 16 rather than 8 because that is what the SysV ABI wants at a function
 * boundary, so the fix does not depend on the guard's threshold. */
.align 16
stack_bottom:
    .skip 4096 * 16
stack_top:
