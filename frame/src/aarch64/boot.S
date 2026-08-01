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

    /* --- Build temporary 4-level page tables ---
     * lo_L0 -> lo_L1 -> Blocks
     * hi_L0 -> hi_L1 -> Blocks
     */
    adrp x0, l0_lo
    add  x0, x0, #:lo12:l0_lo
    mov  x1, #0
1:  str  xzr, [x0, x1]
    add  x1, x1, #8
    cmp  x1, #(4096 * 6)    /* lo_L0, lo_L1, hi_L0, hi_L1, l2_lo_1, l2_hi_1 */
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
     *   [4:2] = AttrIndx (0=Device, 1=Normal, per MAIR_EL1 below)
     *   [10]  = AF  (access flag — else fault on first access)
     *
     * 0x401 = bit 0 + bit 10              → valid, AttrIndx=0 (Device)
     * 0x405 = bit 0 + bit 2 + bit 10      → valid, AttrIndx=1 (Normal)
     * (earlier 0x404 had bit 0 CLEAR = INVALID, causing translation
     * fault on first post-MMU instruction fetch at PA 0x40080000.)
     */
    add  x0, x0, #4096      /* x0 = &lo_L1 */
    mov  x1, #0x401         /* valid block, AttrIndx=0 (Device), PA 0x0 */
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
     * 0x401 = valid block, AttrIndx=0 (Device, per MAIR_EL1). */
    mov  x1, #0x401
    mov  x5, #0x60
    orr  x1, x1, x5, lsl #48    /* PXN (53) | UXN (54) */
    str  x1, [x0, #(0 * 8)]

    /* ── Demote both 1 GiB RAM blocks to 2 MiB, NX outside kernel text ──
     *
     * These two blocks used to be plain `0x405`: valid, Normal, AF, and
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

    adrp x0, l2_hi_1
    add  x0, x0, #:lo12:l2_hi_1
    ldr  x1, =__kernel_start
    ldr  x2, =__text_end_phys
    bl   build_ram_l2
    adrp x3, l1_hi
    add  x3, x3, #:lo12:l1_hi
    adrp x0, l2_hi_1
    add  x0, x0, #:lo12:l2_hi_1
    orr  x0, x0, #0x3
    str  x0, [x3, #(1 * 8)]

    dsb sy

    /* MAIR_EL1: Attr0 = Device nGnRE (0x04), Attr1 = Normal WB (0xFF).
     *
     * The bytes are low-to-high: bits[7:0]=Attr0, bits[15:8]=Attr1.
     * Encoding 0xFF04 gives Attr0=0x04=Device, Attr1=0xFF=Normal —
     * matching the AttrIndx values in the block descriptors above.
     * (Earlier 0x04FF had them swapped, causing the RAM region to be
     * mapped as Device memory, which breaks instruction-fetch ordering
     * on modern cores.)
     */
    mov  x0, #0xFF04
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
    bl  _start_rust

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
build_ram_l2:
    mov  x3, #0                 /* i */
    movz x4, #0x4000, lsl #16   /* pa = 0x4000_0000 */
2:
    mov  x5, #0x405             /* valid block | AttrIndx=1 (Normal) | AF */
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

.align 4
stack_bottom:
    .skip 4096 * 16
.global stack_top
stack_top:
