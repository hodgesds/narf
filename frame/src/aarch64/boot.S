/*
 * NARF aarch64 boot stub.
 */

.section .boot, "ax"
.global _start
.type _start, @function
_start:
    /* Save the incoming DTB pointer. */
    mov x19, x0

    /* Stack in .boot.data. Physical base. */
    adrp x0, stack_top
    add  x0, x0, #:lo12:stack_top
    mov  sp, x0

    /* ─── Build temporary 3-level page tables ─── */
    adrp x0, l1_lo
    add  x0, x0, #:lo12:l1_lo
    mov  x1, #0
1:  str  xzr, [x0, x1]
    add  x1, x1, #8
    cmp  x1, #8192      /* Two 4KB tables */
    b.ne 1b

    /* L1_lo (Identity) */
    mov  x1, #0x401     /* Valid | AF | SH_Inner | Attr0(Device) | 0x0 */
    str  x1, [x0, #0]   
    mov  x1, #0x404     /* Valid | AF | SH_Inner | Attr1(Normal) | 0x4000_0000 */
    movk x1, #0x4000, lsl #16
    str  x1, [x0, #8]

    /* L1_hi (Higher-half @ -2 GiB / 0xFFFFFFFF80000000)
     * Index 510 in 39-bit VA space.
     * Maps to physical RAM base 0x4000_0000.
     */
    adrp x0, l1_hi
    add  x0, x0, #:lo12:l1_hi
    mov  x1, #0x404
    movk x1, #0x4000, lsl #16
    str  x1, [x0, #(510 * 8)]

    /* MAIR_EL1 */
    mov  x0, #0x04FF
    msr  mair_el1, x0

    /* TCR_EL1: T0SZ=25, T1SZ=25, TG1=4KB, SH=Inner, ORGN/IRGN=WB */
    mov  x0, #25
    mov  x1, #25
    orr  x0, x0, x1, lsl #16
    mov  x1, #3
    orr  x0, x0, x1, lsl #12
    orr  x0, x0, x1, lsl #28
    mov  x1, #1
    orr  x0, x0, x1, lsl #10
    orr  x0, x0, x1, lsl #26
    orr  x0, x0, x1, lsl #8
    orr  x0, x0, x1, lsl #24
    mov  x1, #2
    orr  x0, x0, x1, lsl #30
    mov  x1, #2
    orr  x0, x0, x1, lsl #32
    msr  tcr_el1, x0
    isb

    adrp x0, l1_lo
    add  x0, x0, #:lo12:l1_lo
    msr  ttbr0_el1, x0
    adrp x0, l1_hi
    add  x0, x0, #:lo12:l1_hi
    msr  ttbr1_el1, x0
    isb

    mrs  x0, sctlr_el1
    orr  x0, x0, #0x1
    orr  x0, x0, #0x4
    orr  x0, x0, #0x1000
    msr  sctlr_el1, x0
    isb

    /* Jump to Virtual. */
    ldr  x0, =_start_rust_virtual
    br   x0

_start_rust_virtual:
    /* Stack update: physical to virtual. Add 0xFFFFFFFF80000000 - 0x40000000 offset.
     * Actually, just reload it via high virtual address.
     */
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
l1_lo:
    .skip 4096
l1_hi:
    .skip 4096
.align 4
stack_bottom:
    .skip 4096 * 16
stack_top:
