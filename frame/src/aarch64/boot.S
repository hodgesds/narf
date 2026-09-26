/*
 * NARF aarch64 boot stub.
 */

.section .boot, "ax"
.global _start
.type _start, @function
_start:
    /* Save the incoming DTB pointer. */
    mov x19, x0

    /* ── Physical relocation ────────────────────────────────────────────
     *
     * Copy the image `KASLR_PHYS_FIXED` bytes up and continue from the copy, so
     * the image's PHYSICAL address is randomized too and not just the VA it
     * appears at. x21 carries the delta from here on; 0 means no relocation.
     *
     * Done first, before anything else touches an address, because
     * `code-model=small` makes almost all of this free: every `adrp`/`add` pair
     * below resolves relative to the PC, so once we are executing the copy the
     * stack, the page tables and their descriptors all name the copy without a
     * single adjustment. x86_64 needs sixteen of them for exactly this reason —
     * `code-model=kernel` addresses its own data absolutely.
     *
     * What is NOT free is `ldr xN, =symbol`: the load is PC-relative but the
     * VALUE in the literal is a link-time address, so every one naming a
     * PHYSICAL address in the image needs the delta added. Those are marked
     * below. Literals holding kernel-half VAs (`stack_top_virt`, `_start_rust`)
     * need nothing: a VA does not move when the image does, and the window
     * built below maps it to the copy.
     */
    ldr  x21, =KASLR_PHYS_FIXED
    cbnz x21, .Lphys_go                 /* pinned: use it verbatim */
    ldr  x0, =KASLR_PHYS_ENABLE
    cbz  x0, .Lphys_done
    b    .Lfdt_pick                     /* falls through to .Lphys_go or
                                         * .Lphys_done; no `bl`, because the
                                         * stack is not set up yet */
.Lphys_go:

    ldr  x0, =__kernel_start            /* link-time phys: NOT slid, the value */
    ldr  x1, =__kernel_end              /* is low-half so the table skips it   */
    add  x1, x1, #15                    /* round up for the 16-byte copy */
    and  x1, x1, #0xFFFFFFFFFFFFFFF0
    add  x2, x0, x21                    /* destination */
1:  ldp  x3, x4, [x0], #16
    stp  x3, x4, [x2], #16
    cmp  x0, x1
    b.lo 1b

    /* The MMU is off, so those stores went to memory rather than a cache, but
     * the I-cache may still hold lines speculatively fetched for the
     * destination. Invalidate before executing there. */
    dsb  sy
    ic   iallu
    dsb  sy
    isb

    /* Continue in the copy. `adr` gives this label's address in the image we
     * are running now — the original — so the delta reaches the copy's. */
    adr  x0, .Lphys_done
    add  x0, x0, x21
    br   x0
.Lphys_done:

    /* Enable FP/SIMD access at EL1 (CPACR_EL1.FPEN = 0b11, bits 21:20).
     *
     * Without this, any SIMD or floating-point instruction the Rust
     * compiler emits (memcpy-style register moves, struct copies at
     * hardfloat targets) raises a synchronous exception with
     * ESR_EL1.EC = 0x07 (Trapped FP/SIMD access). Target is
     * `aarch64-unknown-none` (hardfloat), which emits SIMD freely.
     *
     * Kernel-mode SIMD use still requires lazy FPU-state save/restore
     * at the trap prologue once Stage 3 adds context switches; Stage 2
     * single-task just needs the access to not trap.
     */
    mrs  x0, cpacr_el1
    orr  x0, x0, #(3 << 20)
    msr  cpacr_el1, x0
    isb

    /* Enable Allocation Tag Access at EL1 (SCTLR_EL1.ATA, bit 43).
     *
     * ATA=1 makes `GCR_EL1`, `TFSR_EL1`, and the MTE tag-memory
     * instructions (STG/LDG/IRG/...) accessible at EL1; without it
     * they #UD. Only takes effect on CPUs that actually support MTE
     * L2 — gated at boot by the feature probe below.
     *
     * Does NOT enable tag checking itself (SCTLR_EL1.TCF stays at
     * its reset value = Ignore). Actual check-mode enable pairs
     * with tag storage in Stage 3.
     */
    mrs  x0, sctlr_el1
    orr  x0, x0, #(1 << 43)
    msr  sctlr_el1, x0
    isb

    /* Allow EL0 to read the virtual counter + frequency
     * (CNTKCTL_EL1.EL0VCTEN, bit 1). The vDSO's __kernel_clock_gettime
     * reads CNTVCT_EL0 from user mode; without this the MRS traps to EL1.
     * (EL0PCTEN/bit 0 is left clear — the vDSO uses the virtual counter,
     * which on QEMU equals the physical one.) */
    mrs  x0, cntkctl_el1
    orr  x0, x0, #(1 << 1)
    msr  cntkctl_el1, x0
    isb

    /* Stack in .boot.data. Physical base. */
    adrp x0, stack_top
    add  x0, x0, #:lo12:stack_top
    mov  sp, x0

    /* ── KASLR: pick a slide and apply the relocation table ─────────────
     *
     * Runs here, with the MMU off and `.boot` executing at its load address,
     * because every site the table names is a PHYSICAL address and every
     * value it patches is a kernel-half VA that nothing may dereference until
     * it has been fixed up.
     *
     * x20 holds the slide from here to the page-table build. x19 already holds
     * the DTB pointer and must survive.
     *
     * Entropy: RNDR (FEAT_RNG, CPUID ID_AA64ISAR0_EL1.RNDR != 0) when the CPU
     * has it, the virtual counter otherwise. CNTVCT alone is boot-time jitter,
     * which `kaslr.rs` already documents as acceptable for slot picking and is
     * what the x86_64 stub falls back to as well.
     */
    mov  x20, #0                        /* slide, filled in below */

    ldr  x0, =KASLR_SLIDE_MASK
    cbz  x0, .Lkaslr_done               /* mask 0 -> KASLR disabled */

    /* A pinned slide skips entropy entirely; it still passes through the mask
     * and alignment below, so it cannot escape the window. */
    ldr  x1, =KASLR_SLIDE_FIXED
    cbnz x1, .Lkaslr_have

    /* ID_AA64ISAR0_EL1.RNDR is bits [63:60]. */
    mrs  x1, id_aa64isar0_el1
    lsr  x1, x1, #60
    cbz  x1, .Lkaslr_tsc
    mrs  x1, s3_3_c2_c4_0               /* RNDR */
    cbnz x1, .Lkaslr_have               /* RNDR reads 0 on failure */
.Lkaslr_tsc:
    mrs  x1, cntvct_el0

.Lkaslr_have:
    and  x1, x1, x0                     /* clamp to the window  */
    and  x1, x1, #0xFFFFFFFFFFE00000    /* 2 MiB align          */
    mov  x20, x1
    cbz  x20, .Lkaslr_done              /* drew zero: nothing to apply */

    /* Record it for the Rust conversions (`kaslr::KERNEL_SLIDE`). */
    ldr  x0, =__kernel_slide_phys
    add  x0, x0, x21                    /* the copy's word, not the original's */
    str  x20, [x0]

    /* Record the physical delta for `kaslr::image_virt_to_phys` and
     * `image_phys_bounds`. The frame allocator reserves those bounds, so a
     * missing delta leaves the running image unreserved and hands it to the
     * buddy. Recorded inside the slide branch is NOT good enough — a zero slide
     * skips to `.Lkaslr_done` — so it is written unconditionally below. */

    /* Apply the table. Header: magic, n_abs64, n_abs32s, n_pcrel32,
     * n_abs64_low, then the site lists as u32 offsets.
     *
     * Both aarch64 lists are 64-bit absolute fields and both resolve to
     * PHYSICAL addresses: image `phys == VA - KERNEL_VIRT_BASE`, so a
     * kernel-half site stored relative to the base IS its physical address,
     * and a low-half site is physical already. One loop covers both.
     * `abs32s` and `pcrel32` are x86_64 classes and are always 0 here.
     */
    ldr  x0, =__kaslr_relocs_phys
    add  x0, x0, x21                    /* the copy's table */
    ldr  w1, [x0]
    mov  w2, #0x534C                    /* "KASL" = 0x4B41534C */
    movk w2, #0x4B41, lsl #16
    cmp  w1, w2
    b.ne .Lkaslr_done                   /* never patched — skip the slide */

    ldr  w3, [x0, #4]                   /* n_abs64                     */
    ldr  w4, [x0, #16]                  /* n_abs64_low                 */
    add  x3, x3, x4                     /* both lists, one loop        */
    add  x5, x0, #20                    /* -> first site offset        */

    /* The abs32s/pcrel32 lists sit between abs64 and abs64_low in the
     * encoding, and are empty on aarch64 — asserted rather than assumed,
     * because a nonzero count would make the second list start elsewhere. */
    ldr  w6, [x0, #8]
    ldr  w7, [x0, #12]
    orr  w6, w6, w7
    cbnz w6, .Lkaslr_bad

.Lkaslr_apply:
    cbz  x3, .Lkaslr_done
    ldr  w6, [x5], #4                   /* site offset == physical addr */
    add  x6, x6, x21                    /* patch the copy, which is what runs */
    ldr  x7, [x6]
    add  x7, x7, x20
    str  x7, [x6]
    sub  x3, x3, #1
    b    .Lkaslr_apply

.Lkaslr_bad:
    /* An x86_64-only list is populated: the encoding is not what this pass
     * expects and the site offsets cannot be trusted. Hang rather than patch
     * the wrong words -- there is no console this early. */
    wfi
    b    .Lkaslr_bad

.Lkaslr_done:

    /* Record the delta unconditionally: every path above can reach here,
     * including "mask is 0" and "drew a zero slide", and Rust's physical
     * conversions need the delta whether or not the image also slid. */
    ldr  x0, =__image_phys_delta_phys
    add  x0, x0, x21
    str  x21, [x0]

    /* --- Build temporary 4-level page tables ---
     * lo_L0 -> lo_L1 -> Blocks
     * hi_L0 -> hi_L1 -> Blocks
     */
    adrp x0, l0_lo
    add  x0, x0, #:lo12:l0_lo
    mov  x1, #0
1:  str  xzr, [x0, x1]
    add  x1, x1, #8
    cmp  x1, #(4096 * 8)    /* + l1_img, l2_img for the image window */
    b.ne 1b

    /* lo_L0[0] -> lo_L1 */
    adrp x0, l0_lo
    add  x0, x0, #:lo12:l0_lo
    add  x1, x0, #4096      /* x1 = &lo_L1 */
    mov  x2, #0x3           /* Table descriptor */
    orr  x1, x1, x2
    str  x1, [x0, #0]
    
    /* lo_L1[0] = 0x0 (Device: AttrIndx=0), lo_L1[1] = 0x4000_0000 (Normal: AttrIndx=1)
     *
     * Block descriptor bits:
     *   [1:0] = 01  (valid block)
     *   [4:2] = AttrIndx (0=Normal, 1=Device, 2=Normal-Tagged, per
     *           MAIR_EL1 below)
     *   [10]  = AF  (access flag — else fault on first access)
     *
     * 0x401 = bit 0 + bit 10              → valid, AttrIndx=0 (Normal)
     * 0x405 = bit 0 + bit 2 + bit 10      → valid, AttrIndx=1 (Device)
     * (earlier 0x404 had bit 0 CLEAR = INVALID, causing translation
     * fault on first post-MMU instruction fetch at PA 0x40080000.)
     */
    add  x0, x0, #4096      /* x0 = &lo_L1 */
    mov  x1, #0x405         /* valid block, AttrIndx=1 (Device), PA 0x0 */
    mov  x5, #0x60
    orr  x1, x1, x5, lsl #48    /* PXN (53) | UXN (54) — see below */
    str  x1, [x0, #0]
    /* lo_L1[1] (PA 0x4000_0000, all of RAM the kernel can reach) is
     * filled in further down, after the L2 demotion, so that only
     * `.boot` — the one thing that executes at a TTBR0 identity address
     * after the MMU comes up — stays executable. */

    /* hi_L0[511] -> hi_L1 */
    adrp x0, l0_hi
    add  x0, x0, #:lo12:l0_hi
    add  x1, x0, #4096      /* x1 = &hi_L1 */
    mov  x2, #0x3
    orr  x1, x1, x2
    str  x1, [x0, #(511 * 8)]
    
    /* hi_L1[1] = 0x4000_0000 (Normal RAM, virt 0xFFFFFF80_40000000)
     *
     * VA 0xFFFFFF80_40080000 decomposes (T1SZ=16, 4 KiB granule) as
     *   bits 47-39 = 511 (L0 index, == hi_L0[511] above)
     *   bits 38-30 = 1   (L1 index, THIS slot)
     *   ...
     * The earlier #(510 * 8) was a copy-paste of x86_64's PDPT[510]
     * convention; aarch64 with this KERNEL_VIRT_BASE wants L1[1],
     * and 510 GiB past the L0 base overflows T1SZ entirely. */
    add  x0, x0, #4096      /* x0 = &hi_L1 */
    /* hi_L1[1] is filled in further down, after the L2 demotion. */

    /* hi_L1[0] = 0x0000_0000 (Device, virt 0xFFFFFF80_00000000).
     *
     * Covers the low-PA MMIO devices (PL011 UART at PA 0x09000000,
     * GIC at PA 0x08000000, etc. on QEMU virt) so kernel-side
     * console writes + interrupt-controller pokes survive a
     * TTBR0 swap to a private user address space. Without this,
     * the moment a user task `activate()`s its empty TTBR0 the
     * next `writeln!(console::Writer, ...)` page-faults.
     *
     * 0x405 = valid block, AttrIndx=1 (Device, per MAIR_EL1). */
    mov  x1, #0x405
    mov  x5, #0x60
    orr  x1, x1, x5, lsl #48    /* PXN (53) | UXN (54) */
    str  x1, [x0, #(0 * 8)]

    /* ── Demote both 1 GiB RAM blocks to 2 MiB, NX outside kernel text ──
     *
     * These two blocks used to be plain `0x401`: valid, Normal, AF, and
     * — because bits 53/54 were clear — **executable at EL1**. Between
     * them they alias every physical page the kernel can reach (the
     * TTBR1 window at PA 0x4000_0000 is what `PhysAddr::kernel_ptr`
     * resolves to, so it covers the whole heap, the buddy arena, and
     * every BPF prog pack) as simultaneously writable and executable.
     * An RX mapping of JIT text elsewhere in the address space is not a
     * W^X boundary while that is true.
     *
     * Each 1 GiB block becomes a table pointing at 512 × 2 MiB blocks,
     * PXN|UXN except where the block overlaps the range that genuinely
     * executes there:
     *
     *   TTBR0 identity : [__kernel_start, __boot_end) — `.boot` runs at
     *     its identity address after the MMU comes up, both on the BSP
     *     (`_start_rust_entry`, below) and on every AP (`smp_entry.S`
     *     does its whole bring-up and `br x1` at a low VA).
     *   TTBR1 window   : [__kernel_start, __text_end_phys) — the kernel
     *     proper.
     *
     * Built here, before `msr sctlr_el1` turns the MMU on, so there is
     * never a live block descriptor to break-before-make against.
     */
    adrp x0, l2_lo_1
    add  x0, x0, #:lo12:l2_lo_1
    /* The executable range is where `.boot` ACTUALLY runs, which after a
     * physical relocation is the copy — this map is the identity one, so the
     * range has to move with the bytes. Leaving it link-time would mark the
     * running `.boot` PXN and fault on the first post-MMU instruction fetch. */
    ldr  x1, =__kernel_start
    add  x1, x1, x21
    ldr  x2, =__boot_end
    add  x2, x2, x21
    bl   build_ram_l2
    adrp x3, l1_lo
    add  x3, x3, #:lo12:l1_lo
    adrp x0, l2_lo_1
    add  x0, x0, #:lo12:l2_lo_1
    orr  x0, x0, #0x3           /* valid + table descriptor */
    str  x0, [x3, #(1 * 8)]

    /* The linear map gets NO executable range. The image executes from its own
     * window (built below), so passing the kernel-text extent here would leave
     * a second executable alias of it — exactly the W^X hole the x86_64 side
     * closed by shrinking its window to the image. An empty range (x1 == x2)
     * makes every block PXN|UXN. */
    adrp x0, l2_hi_1
    add  x0, x0, #:lo12:l2_hi_1
    mov  x1, #0
    mov  x2, #0
    bl   build_ram_l2
    adrp x3, l1_hi
    add  x3, x3, #:lo12:l1_hi
    adrp x0, l2_hi_1
    add  x0, x0, #:lo12:l2_hi_1
    orr  x0, x0, #0x3
    str  x0, [x3, #(1 * 8)]

    /* ── The kernel image's own window ──────────────────────────────────
     *
     * VA = phys + KIMAGE_VOFFSET + slide, which is where the image is linked
     * and (after the apply pass above) where every absolute address in it now
     * points. `KIMAGE_VOFFSET` is 1 GiB aligned, so VA and phys share 2 MiB
     * alignment and a block mapping places the image exactly.
     *
     * hi_L0[510] -> l1_img -> l2_img, and l2_img[ (slide>>21) + i ] maps
     * phys 0x4000_0000 + i*2MiB. The module window lives at l2_img[448..] and
     * is populated later by `module_text`; the linker ASSERTs that the image
     * plus the widest slide cannot reach it.
     */
    adrp x0, l0_hi
    add  x0, x0, #:lo12:l0_hi
    adrp x1, l1_img
    add  x1, x1, #:lo12:l1_img
    orr  x1, x1, #0x3
    str  x1, [x0, #(510 * 8)]

    adrp x0, l1_img
    add  x0, x0, #:lo12:l1_img
    adrp x1, l2_img
    add  x1, x1, #:lo12:l2_img
    orr  x1, x1, #0x3
    str  x1, [x0, #(511 * 8)]

    adrp x0, l2_img
    add  x0, x0, #:lo12:l2_img
    ldr  x1, =__kernel_start        /* exec range: kernel text, physical */
    ldr  x2, =__text_end_phys
    ldr  x4, =__kernel_end          /* image end, physical                */
    mov  x3, x20                    /* slide                             */
    mov  x10, x21                   /* physical relocation delta         */
    bl   build_image_l2

    dsb sy

    /* MAIR_EL1: Attr0 = Normal WB (0xFF), Attr1 = Device nGnRE (0x04),
     * Attr2 = Normal WB Tagged (0xF0).
     *
     * Bytes low-to-high: [7:0]=Attr0, [15:8]=Attr1, [23:16]=Attr2, so
     * 0xF004FF. Normal is index 0 deliberately: `map_4kb` composes a leaf as
     * `default | caller_flags`, and an index field cannot be OR-ed. With
     * Normal at 0 the default contributes nothing to bits [4:2], so a caller
     * asking for Device (1) or Tagged (2) gets exactly that. Any other
     * ordering silently ORs two indices together -- Device|Normal would have
     * mapped MMIO cacheable.
     *
     * Attr2 is inert until a descriptor selects AttrIndx=2. MTE tag checks
     * apply only to Tagged Normal memory, so without it no page can be
     * checked whatever SCTLR_EL1.TCF says.
     *
     * movz/movk: 0xF004FF does not fit a `mov` immediate. */
    movz x0, #0x04FF
    movk x0, #0xF0, lsl #16
    msr  mair_el1, x0

    /* TCR_EL1: 48-bit VA, TG=4KB */
    mov  x0, #16
    orr  x0, x0, #(16 << 16)    /* T0SZ | T1SZ */
    orr  x0, x0, #(3 << 12)     /* SH0 */
    orr  x0, x0, #(3 << 28)     /* SH1 */
    orr  x0, x0, #(1 << 10)     /* ORGN0 */
    orr  x0, x0, #(1 << 26)     /* ORGN1 */
    orr  x0, x0, #(1 << 8)      /* IRGN0 */
    orr  x0, x0, #(1 << 24)     /* IRGN1 */
    orr  x0, x0, #(2 << 30)     /* TG1=4KB */
    mov  x1, #0x62              /* IPS=40-bit, TBI0=1, TBI1=1 */
    orr  x0, x0, x1, lsl #32
    msr  tcr_el1, x0
    isb

    /* TTBR0/1 */
    adrp x0, l0_lo
    add  x0, x0, #:lo12:l0_lo
    msr  ttbr0_el1, x0
    adrp x0, l0_hi
    add  x0, x0, #:lo12:l0_hi
    msr  ttbr1_el1, x0
    
    ic   ialluis
    dsb  sy
    isb

    /* Enable MMU */
    mrs  x0, sctlr_el1
    orr  x0, x0, #0x1           /* M=1 */
    orr  x0, x0, #0x1000        /* I=1 */
    msr  sctlr_el1, x0
    dsb  sy
    isb

    /* Jump to Virtual.
     *
     * `_start_rust_entry` is in `.boot`, so this literal holds a low link-time
     * address: without the delta it branches back into the ORIGINAL image,
     * which still exists and still looks valid. (x86_64 had the same bug in its
     * far return into long mode, where it cost a boot that faulted on the first
     * call into Rust.) */
    ldr  x0, =_start_rust_entry
    add  x0, x0, x21
    br   x0

_start_rust_entry:
    /* Switch to the high-VA stack alias. The pre-MMU bring-up
     * above used the low-VA `stack_top` (set via `adrp` at line
     * 46-48); after the MMU is up + we've branched into the
     * high-half via `br x0`, kernel code must run on a stack
     * that lives inside TTBR1's mapping. `stack_top_virt` is
     * defined in `build/linker/aarch64.ld` as `stack_top +
     * KERNEL_VIRT_BASE` and resolves to a high-VA address
     * pointing at the same physical bytes as the boot stack. */
    ldr  x0, =stack_top_virt
    mov  sp, x0

    mov x0, #0xfeed
    movk x0, #0xd00d, lsl #16
    mov x1, x19
    /* Indirect through a literal, not `bl _start_rust`.
     *
     * `.boot` is linked low (KERNEL_LOAD_BASE) and `_start_rust` is in the
     * kernel half, so a direct `bl` is ~512 GiB out of CALL26's +/-128 MiB
     * range and LLD silently inserts a range-extension thunk:
     *
     *     ldr x16, [pc+8] ; br x16 ; .quad _start_rust
     *
     * That `.quad` holds a kernel-half address and carries NO relocation
     * record -- LLD resolves it at link time, so `--emit-relocs` reports
     * nothing and a KASLR slide cannot see it. The x86_64 GOT is invisible
     * for exactly this reason and needs its own fixup pass; here the whole
     * problem is avoidable. A literal loaded with `ldr =` gets a real
     * R_AARCH64_ABS64 record, which the relocation table already carries.
     *
     * x16 is IP0, the register a veneer is allowed to clobber, and x0/x1 hold
     * the arguments. */
    ldr x16, =_start_rust
    blr x16

1:  wfi
    b 1b
.size _start, . - _start

/* Fill a 512-entry L2 table covering PA 0x4000_0000..0x8000_0000 with
 * 2 MiB block descriptors, PXN|UXN except where the block overlaps
 * [x1, x2).
 *
 *   x0 = &l2 table
 *   x1 = exec_start (physical, inclusive)
 *   x2 = exec_end   (physical, exclusive)
 *
 * Clobbers x3-x9, and x11 in `build_image_l2`. Runs pre-MMU at a low PA, so it
 * must stay in `.boot`.
 */

/* ── Physical relocation target selection from the DTB ───────────────────
 *
 * Reached by a `b` (not `bl`) from the relocation block above, because `sp` is
 * not set up yet: this runs before the stack pointer is established, so nothing
 * here may push. It exits by branching to `.Lphys_go` with x21 = delta, or to
 * `.Lphys_done` to decline. `bl` IS used for one leaf helper below — x30 is
 * otherwise unused this early, and the helper never nests.
 *
 * In:  x19 = DTB pointer, as the loader left it in x0.
 * Out: x21 = chosen delta (branching to .Lphys_go), or no relocation.
 *
 * Why a DTB walk rather than the flat array the x86_64 side reads: the PVH
 * handoff hands over `(memmap_paddr, memmap_entries)` and every entry is a
 * fixed 24-byte record. A devicetree has neither — RAM extent lives in
 * `/memory`'s `reg`, the initrd bounds in `/chosen`, and reaching either means
 * walking the structure block token by token with the strings block as a side
 * table. Everything is big-endian, so every field needs a `rev`.
 *
 * The walk deliberately keys on PROPERTY names, never node names:
 *
 *   - `reg` is not unique (almost every node has one), so a `reg` is only
 *     remembered as a candidate; a `device_type = "memory"` in the same node is
 *     what commits it as RAM. The QEMU virt DTB emits `reg` BEFORE
 *     `device_type`, which is why it is remembered rather than looked up.
 *   - `linux,initrd-start` / `linux,initrd-end` ARE unique, so they need no
 *     node context at all.
 *
 * That avoids parsing node names ("memory@40000000" needs a prefix match, and
 * the unit address varies by machine) — the name bytes are only skipped, never
 * compared. Property values may be 4-byte aligned, so every 64-bit field is
 * read as two 32-bit halves.
 *
 * Anything unexpected — bad magic, an unknown token, a `reg` that is not
 * 2+2 cells, more ranges than the small fixed tables hold — declines rather
 * than guesses. Failing closed costs the randomization; guessing costs the boot.
 */


.Lfdt_pick:
    /* ── Locate the DTB ──
     *
     * x19 holds whatever was in x0 at entry, which for the Linux arm64 boot
     * protocol is the DTB's physical address. QEMU's `-kernel` does NOT follow
     * that protocol for a raw ELF — it jumps to the ELF entry with the registers
     * zeroed — so x19 is 0 on the path this tree actually boots, and relying on
     * it silently declined to relocate at all.
     *
     * Same three-step search the Rust side already does in `scan_for_dtb`:
     * the handoff pointer, then the fixed address xtask force-loads the blob at,
     * then a bounded scan of low RAM for the magic.
     */
    movz w1, #0xfeed
    movk w1, #0xd00d, lsl #16           /* w1 = FDT magic, host order */

    mov  x2, x19                        /* 1. the handoff pointer */
    cbz  x2, 1f
    ldr  w0, [x2]
    rev  w0, w0
    cmp  w0, w1
    b.eq .Lfdt_have

1:  movz x2, #0x4F00, lsl #16           /* 2. DTB_LOAD_ADDR */
    ldr  w0, [x2]
    rev  w0, w0
    cmp  w0, w1
    b.eq .Lfdt_have

    /* 3. Scan [0x4000_0000, 0x5000_0000) on 4-byte strides. Bounded, and the
     * same window the Rust fallback uses. */
    movz x2, #0x4000, lsl #16
    movz x3, #0x5000, lsl #16
2:  cmp  x2, x3
    b.hs .Lphys_done                    /* no DTB anywhere: decline */
    ldr  w0, [x2]
    rev  w0, w0
    cmp  w0, w1
    b.eq .Lfdt_have
    add  x2, x2, #4
    b    2b

.Lfdt_have:
    mov  x19, x2                        /* the DTB the rest of the walk reads */

    ldr  w2, [x19, #4]                  /* totalsize   */
    rev  w2, w2
    ldr  w3, [x19, #8]                  /* off_dt_struct */
    rev  w3, w3
    ldr  w4, [x19, #12]                 /* off_dt_strings */
    rev  w4, w4

    /* Reset the tables, then record the DTB itself as the first thing the copy
     * must not land on. */
    adrp x9, fdt_nram
    add  x9, x9, #:lo12:fdt_nram
    str  xzr, [x9]                      /* fdt_nram = 0 */
    adrp x9, fdt_navoid
    add  x9, x9, #:lo12:fdt_navoid
    str  xzr, [x9]                      /* fdt_navoid = 0 */
    adrp x9, fdt_initrd_start
    add  x9, x9, #:lo12:fdt_initrd_start
    str  xzr, [x9]
    str  xzr, [x9, #8]                  /* fdt_initrd_end */

    mov  x0, x19                        /* DTB base */
    mov  x1, x2                         /* totalsize */
    bl   .Lfdt_add_avoid

    add  x4, x19, x4                    /* x4 = strings block */
    add  x5, x19, x3                    /* x5 = cursor into struct block */
    add  x6, x19, x2                    /* x6 = hard bound (dtb + totalsize) */
    mov  x24, #0                        /* have a remembered `reg` */

.Lfdt_tok:
    cmp  x5, x6
    b.hs .Lfdt_walk_done                /* ran off the end without FDT_END */
    ldr  w8, [x5]
    rev  w8, w8
    add  x5, x5, #4
    cmp  w8, #1                         /* FDT_BEGIN_NODE */
    b.eq .Lfdt_begin
    cmp  w8, #2                         /* FDT_END_NODE   */
    b.eq .Lfdt_endnode
    cmp  w8, #3                         /* FDT_PROP       */
    b.eq .Lfdt_prop
    cmp  w8, #4                         /* FDT_NOP        */
    b.eq .Lfdt_tok
    cmp  w8, #9                         /* FDT_END        */
    b.eq .Lfdt_walk_done
    b    .Lphys_done                    /* unknown token: decline */

.Lfdt_begin:
    /* Skip the NUL-terminated node name, then 4-align. Never compared — see
     * the header comment. */
    mov  x24, #0                        /* new node: forget any `reg` */
1:  ldrb w9, [x5], #1
    cbnz w9, 1b
    add  x5, x5, #3
    and  x5, x5, #0xFFFFFFFFFFFFFFFC
    b    .Lfdt_tok

.Lfdt_endnode:
    mov  x24, #0
    b    .Lfdt_tok

.Lfdt_prop:
    ldr  w10, [x5]                      /* plen   */
    rev  w10, w10
    ldr  w11, [x5, #4]                  /* nameoff */
    rev  w11, w11
    add  x5, x5, #8
    mov  x25, x5                        /* value */
    mov  x26, x10                       /* plen  */
    /* Advance past the value now, 4-aligned, so every branch below can just
     * fall back to .Lfdt_tok. */
    add  x5, x5, x10
    add  x5, x5, #3
    and  x5, x5, #0xFFFFFFFFFFFFFFFC

    add  x13, x4, x11                   /* property name — kept HERE, because
                                         * `.Lfdt_streq` advances the pointers it
                                         * is given, so every compare below has
                                         * to start from a fresh copy */

    /* `reg`: remember it as a candidate. 2 address cells + 2 size cells is
     * 16 bytes; anything else is a layout this code does not model. */
    mov  x9, x13
    adr  x10, .Lfdt_s_reg
    bl   .Lfdt_streq
    cbz  w12, 2f
    cmp  x26, #16
    b.ne .Lfdt_tok
    mov  x0, x25
    bl   .Lfdt_be64
    mov  x22, x0                        /* base */
    add  x0, x25, #8
    bl   .Lfdt_be64
    mov  x23, x0                        /* size */
    mov  x24, #1
    b    .Lfdt_tok

2:  /* `device_type`: commits the remembered `reg` when the value is "memory". */
    mov  x9, x13
    adr  x10, .Lfdt_s_devtype
    bl   .Lfdt_streq
    cbz  w12, 3f
    cbz  x24, .Lfdt_tok                 /* no `reg` in this node */
    mov  x9, x25                        /* compare the VALUE */
    adr  x10, .Lfdt_s_memory
    bl   .Lfdt_streq
    cbz  w12, .Lfdt_tok
    mov  x0, x22
    mov  x1, x23
    bl   .Lfdt_add_ram
    mov  x24, #0
    b    .Lfdt_tok

3:  /* `linux,initrd-start` / `-end`: unique, so no node context needed. The
     * FDT spec allows either width for these, and QEMU's choice varies. */
    mov  x9, x13
    adr  x10, .Lfdt_s_initrd_start
    bl   .Lfdt_streq
    cbz  w12, 4f
    mov  x0, x25
    mov  x1, x26
    bl   .Lfdt_cellval
    adrp x9, fdt_initrd_start
    add  x9, x9, #:lo12:fdt_initrd_start
    str  x0, [x9]
    b    .Lfdt_tok

4:  mov  x9, x13
    adr  x10, .Lfdt_s_initrd_end
    bl   .Lfdt_streq
    cbz  w12, .Lfdt_tok
    mov  x0, x25
    mov  x1, x26
    bl   .Lfdt_cellval
    adrp x9, fdt_initrd_start
    add  x9, x9, #:lo12:fdt_initrd_start
    str  x0, [x9, #8]
    b    .Lfdt_tok

.Lfdt_walk_done:
    /* The initrd, if the loader passed one. Clobbering it would destroy the
     * rootfs while the copy itself reported success. */
    adrp x9, fdt_initrd_start
    add  x9, x9, #:lo12:fdt_initrd_start
    ldr  x0, [x9]
    ldr  x1, [x9, #8]
    cbz  x0, 5f
    cmp  x1, x0
    b.ls 5f
    sub  x1, x1, x0
    bl   .Lfdt_add_avoid
5:
    /* No RAM node found: decline rather than guess at an extent. */
    adrp x9, fdt_nram
    add  x9, x9, #:lo12:fdt_nram
    ldr  x0, [x9]
    cbz  x0, .Lphys_done

    /* Image span and floor, both 2 MiB rounded. Placing at or above the image's
     * end keeps the delta positive and no smaller than the image, so the
     * forward copy cannot overwrite its own source. */
    ldr  x9, =__kernel_start
    ldr  x10, =__kernel_end
    sub  x11, x10, x9
    add  x11, x11, #0xfff                   /* + (2 MiB - 1): an `add` immediate */
    add  x11, x11, #0x1ff, lsl #12          /* is 12 bits, so it takes two */
    and  x11, x11, #0xFFFFFFFFFFE00000
    adrp x12, fdt_span
    add  x12, x12, #:lo12:fdt_span
    str  x11, [x12]                         /* fdt_span */
    add  x13, x10, #0xfff
    add  x13, x13, #0x1ff, lsl #12
    and  x13, x13, #0xFFFFFFFFFFE00000
    str  x13, [x12, #8]                     /* fdt_floor */

    mov  x27, #64                           /* attempts */
.Lfdt_try:
    cbz  x27, .Lphys_done
    sub  x27, x27, #1

    /* Sample the DELTA, not the target.
     *
     * The image window maps 2 MiB BLOCKS, and a block descriptor's output
     * address must be 2 MiB aligned. `__kernel_start` is 0x4008_0000 here — 512
     * KiB aligned, NOT 2 MiB — so a 2 MiB aligned TARGET yields a delta that is
     * not, every mapped output address inherits that misalignment, and the
     * descriptors are malformed: the boot hangs the moment the MMU comes up.
     * (x86_64 never hit this because its load base is 16 MiB aligned, so there
     * the two are interchangeable.)
     *
     * Aligning the delta instead keeps `link_pa + delta` aligned for every
     * block, and the target inherits the load base's own offset. */
    bl   .Lfdt_rand                         /* x0 = random */
    and  x0, x0, #0x7FE00000                /* 2 MiB aligned delta, < 2 GiB */
    adrp x12, fdt_span
    add  x12, x12, #:lo12:fdt_span
    ldr  x11, [x12]                         /* span */
    cmp  x0, x11
    b.lo .Lfdt_try                          /* delta < image span: the forward
                                             * copy would eat its own source */
    ldr  x9, =__kernel_start
    add  x0, x9, x0                         /* target = load base + delta */
    add  x14, x0, x11
    /* The TTBR0 identity map covers 0..2 GiB (lo_L1[0..1]); `.boot` executes at
     * its physical address after the MMU comes up, so the copy must land inside
     * that window. */
    movz x15, #0x8000, lsl #16              /* 2 GiB */
    cmp  x14, x15
    b.hi .Lfdt_try

    mov  x28, x0                            /* candidate */
    bl   .Lfdt_in_ram
    cbz  w12, .Lfdt_try
    bl   .Lfdt_clear
    cbz  w12, .Lfdt_try

    ldr  x9, =__kernel_start
    sub  x21, x28, x9
    b    .Lphys_go

/* x9, x10 = NUL-terminated strings. w12 = 1 if equal. Clobbers x9-x12.
 * A leaf: called with `bl` from the walk, never nested. */
.Lfdt_streq:
    ldrb w11, [x9], #1
    ldrb w12, [x10], #1
    cmp  w11, w12
    b.ne 1f
    cbnz w11, .Lfdt_streq
    mov  w12, #1
    ret
1:  mov  w12, #0
    ret

/* x0 = pointer to a big-endian 64-bit FDT value, possibly only 4-byte aligned,
 * so it is read as two halves. Returns x0. */
.Lfdt_be64:
    ldr  w9, [x0]
    rev  w9, w9
    ldr  w10, [x0, #4]
    rev  w10, w10
    lsl  x9, x9, #32
    orr  x0, x9, x10
    ret

/* x0 = value pointer, x1 = property length. Returns x0 = the value, accepting
 * both the 4-byte and 8-byte encodings the FDT spec allows. Length 0 or any
 * other size yields 0, which the caller treats as absent. */
.Lfdt_cellval:
    cmp  x1, #4
    b.ne 1f
    ldr  w9, [x0]
    rev  w9, w9
    mov  x0, x9
    ret
1:  cmp  x1, #8
    b.ne 2f
    b    .Lfdt_be64
2:  mov  x0, #0
    ret

/* x0 = base, x1 = size. Appends a RAM range, ignoring empties and declining the
 * whole selection if the table is full. */
.Lfdt_add_ram:
    cbz  x1, 9f
    adrp x9, fdt_nram
    add  x9, x9, #:lo12:fdt_nram
    ldr  x10, [x9]
    cmp  x10, #4
    b.hs .Lphys_done                    /* more memory nodes than modelled */
    adrp x11, fdt_ram
    add  x11, x11, #:lo12:fdt_ram
    add  x11, x11, x10, lsl #4
    stp  x0, x1, [x11]
    add  x10, x10, #1
    str  x10, [x9]
9:  ret

/* x0 = base, x1 = length. Appends an avoid range, same rules. */
.Lfdt_add_avoid:
    cbz  x1, 9f
    adrp x9, fdt_navoid
    add  x9, x9, #:lo12:fdt_navoid
    ldr  x10, [x9]
    cmp  x10, #8
    b.hs .Lphys_done
    adrp x11, fdt_avoid
    add  x11, x11, #:lo12:fdt_avoid
    add  x11, x11, x10, lsl #4
    stp  x0, x1, [x11]
    add  x10, x10, #1
    str  x10, [x9]
9:  ret

/* w12 = 1 if [x28, x28 + span) lies entirely inside ONE RAM range. Straddling
 * two is rejected: adjacent table entries need not be adjacent in reality. */
.Lfdt_in_ram:
    adrp x9, fdt_nram
    add  x9, x9, #:lo12:fdt_nram
    ldr  x10, [x9]
    adrp x11, fdt_ram
    add  x11, x11, #:lo12:fdt_ram
    adrp x13, fdt_span
    add  x13, x13, #:lo12:fdt_span
    ldr  x13, [x13]
    add  x14, x28, x13                  /* candidate end */
1:  cbz  x10, 8f
    ldp  x15, x16, [x11]
    add  x16, x15, x16                  /* range end */
    cmp  x28, x15
    b.lo 2f
    cmp  x14, x16
    b.hi 2f
    mov  w12, #1
    ret
2:  add  x11, x11, #16
    sub  x10, x10, #1
    b    1b
8:  mov  w12, #0
    ret

/* w12 = 1 if [x28, x28 + span) overlaps nothing on the avoid list. Two ranges
 * are disjoint iff one ends at or before the other begins. */
.Lfdt_clear:
    adrp x9, fdt_navoid
    add  x9, x9, #:lo12:fdt_navoid
    ldr  x10, [x9]
    adrp x11, fdt_avoid
    add  x11, x11, #:lo12:fdt_avoid
    adrp x13, fdt_span
    add  x13, x13, #:lo12:fdt_span
    ldr  x13, [x13]
    add  x14, x28, x13                  /* candidate end */
1:  cbz  x10, 8f
    ldp  x15, x16, [x11]
    add  x16, x15, x16                  /* avoid end */
    cmp  x15, x14
    b.hs 2f                             /* starts at or after our end */
    cmp  x28, x16
    b.hs 2f                             /* we start at or after its end */
    mov  w12, #0                        /* overlap */
    ret
2:  add  x11, x11, #16
    sub  x10, x10, #1
    b    1b
8:  mov  w12, #1
    ret

/* x0 = 64 random bits. RNDR when the CPU has FEAT_RNG, the virtual counter
 * otherwise — the same source and the same caveat as the slide: CNTVCT alone is
 * boot-time jitter. */
.Lfdt_rand:
    mrs  x9, id_aa64isar0_el1
    lsr  x9, x9, #60
    cbz  x9, 1f
    mrs  x0, s3_3_c2_c4_0               /* RNDR */
    cbnz x0, 2f                         /* reads 0 on failure */
1:  mrs  x0, cntvct_el0
2:  ret

.Lfdt_s_reg:           .asciz "reg"
.Lfdt_s_devtype:       .asciz "device_type"
.Lfdt_s_memory:        .asciz "memory"
.Lfdt_s_initrd_start:  .asciz "linux,initrd-start"
.Lfdt_s_initrd_end:    .asciz "linux,initrd-end"
.align 2

/* Fill `l2_img` for the kernel image.
 *
 * x0 = &l2_img, x1 = exec_start (phys), x2 = exec_end (phys),
 * x3 = slide, x4 = image end (phys), x10 = physical relocation delta.
 *
 * Entry index is `(slide >> 21) + i` and the output PA is
 * `0x4000_0000 + i*2MiB + delta`, for i covering 0x4000_0000 .. page_up_2M(x4).
 *
 * The loop counter, the bound and the exec range all stay in LINK-TIME space
 * and only the descriptor's output address gets the delta. Keeping the delta
 * out of the bound is deliberate: it is the VA extent that decides how many
 * entries this window needs, and folding a relocation into it would inflate the
 * count by the delta — the same confusion that, on x86_64, grew the window from
 * 49 leaves to 176 and overran the PD the slide has to fit inside.
 *
 * The
 * image starts at `KERNEL_LOAD_BASE` (0x4008_0000), part-way into the first
 * block, so that block is mapped too — it also holds `.boot`, which is
 * harmless here: this window is never used to execute `.boot`, and the block
 * is PXN|UXN unless it overlaps kernel text.
 */
build_image_l2:
    lsr  x3, x3, #21            /* slide in 2 MiB units -> index offset */
    mov  x5, #0                 /* i */
    movz x6, #0x4000, lsl #16   /* pa = 0x4000_0000 */
1:
    mov  x7, #0x401             /* valid block | AttrIndx=0 (Normal) | AF */
    add  x8, x6, #0x200000      /* pa_end */
    /* Overlap with the exec range iff pa < exec_end && exec_start < pa_end. */
    cmp  x6, x2
    b.hs 2f
    cmp  x1, x8
    b.lo 3f
2:
    mov  x9, #0x60
    orr  x7, x7, x9, lsl #48    /* PXN (53) | UXN (54) */
3:
    add  x11, x6, x10           /* output PA = link-time PA + delta */
    orr  x7, x7, x11            /* | output PA */
    add  x9, x5, x3             /* entry index = i + (slide >> 21) */
    str  x7, [x0, x9, lsl #3]
    mov  x6, x8
    add  x5, x5, #1
    /* Continue while pa < image end. */
    cmp  x6, x4
    b.lo 1b
    ret

build_ram_l2:
    mov  x3, #0                 /* i */
    movz x4, #0x4000, lsl #16   /* pa = 0x4000_0000 */
2:
    mov  x5, #0x401             /* valid block | AttrIndx=0 (Normal) | AF */
    add  x6, x4, #0x200000      /* pa_end */
    /* Overlap iff  pa < exec_end  &&  exec_start < pa_end. */
    cmp  x4, x2
    b.hs 3f
    cmp  x1, x6
    b.lo 4f
3:
    mov  x7, #0x60
    orr  x5, x5, x7, lsl #48    /* PXN (53) | UXN (54) */
4:
    orr  x5, x5, x4             /* | output PA */
    str  x5, [x0, x3, lsl #3]
    mov  x4, x6
    add  x3, x3, #1
    cmp  x3, #512
    b.ne 2b
    ret

.section .boot.data, "aw"
.align 12
l0_lo:
    .skip 4096
l1_lo:
    .skip 4096
l0_hi:
    .skip 4096
l1_hi:
    .skip 4096
/* L2 demotions of the two 1 GiB RAM blocks. Zeroed by the same loop at
 * the top of `_start`, which is why its bound says `4096 * 6`. */
l2_lo_1:
    .skip 4096
l2_hi_1:
    .skip 4096
/* The kernel image's own window, at L0[510]/L1[511]. Separate from the linear
 * map above so the image can slide without rewriting entries that map
 * unrelated physical addresses. The module window shares this L1 slot at
 * L2[448..]; the image sits at L2[0..] plus its slide. */
l1_img:
    .skip 4096
l2_img:
    .skip 4096

.align 4
/* Scratch for `.Lfdt_pick`: RAM ranges and avoid ranges harvested from the DTB,
 * plus the image span and floor. Dead once the copy is done. */
.align 3
fdt_nram:          .quad 0
fdt_ram:           .space 4 * 16        /* 4 x (base, size); `.fill n,16` would
                                          * silently truncate the element size
                                          * to 8 and halve the table */
fdt_navoid:        .quad 0
fdt_avoid:         .space 8 * 16        /* 8 x (base, len) */
fdt_initrd_start:  .quad 0
fdt_initrd_end:    .quad 0
fdt_span:          .quad 0
fdt_floor:         .quad 0

stack_bottom:
    .skip 4096 * 16
.global stack_top
stack_top:
