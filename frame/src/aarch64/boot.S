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
    cmp  x1, #(4096 * 4)    /* lo_L0, lo_L1, hi_L0, hi_L1 */
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
    str  x1, [x0, #0]
    mov  x1, #0x405         /* valid block, AttrIndx=1 (Normal), PA 0x4000_0000 */
    movk x1, #0x4000, lsl #16
    str  x1, [x0, #8]

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
    mov  x1, #0x405
    movk x1, #0x4000, lsl #16
    str  x1, [x0, #(1 * 8)]

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
    mov  x1, #2
    orr  x0, x0, x1, lsl #32    /* IPS=40-bit */
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
    ldr  x0, =stack_top
    mov  sp, x0

    mov x0, #0xfeed
    movk x0, #0xd00d, lsl #16
    mov x1, x19
    bl  _start_rust

1:  wfi
    b 1b
.size _start, . - _start

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

.align 4
stack_bottom:
    .skip 4096 * 16
stack_top:
