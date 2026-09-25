/*
 * NARF aarch64 boot stub.
 */

.section .boot, "ax"
.global _start
.type _start, @function
_start:
    /* Save the incoming DTB pointer. */
    mov x19, x0

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
    str  x20, [x0]

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
    ldr  x1, =__kernel_start
    ldr  x2, =__boot_end
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

    /* Jump to Virtual */
    ldr  x0, =_start_rust_entry
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
 * Clobbers x3-x7. Runs pre-MMU at a low PA, so it must stay in `.boot`.
 */
/* Fill `l2_img` for the kernel image.
 *
 * x0 = &l2_img, x1 = exec_start (phys), x2 = exec_end (phys),
 * x3 = slide, x4 = image end (phys).
 *
 * Entry index is `(slide >> 21) + i` and the output PA is
 * `0x4000_0000 + i*2MiB`, for i covering 0x4000_0000 .. page_up_2M(x4). The
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
    orr  x7, x7, x6             /* | output PA */
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
stack_bottom:
    .skip 4096 * 16
.global stack_top
stack_top:
