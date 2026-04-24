/*
 * NARF aarch64 boot stub.
 */

.section .boot, "ax"
.global _start
.type _start, @function
_start:
    /* Save the incoming DTB pointer. */
    mov x19, x0

    /* Stack in .boot.data. No MMU yet, so this is physical. */
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
    mov  x1, #0x401     /* Valid | AF | SH_Inner | Attr0(Device) */
    str  x1, [x0, #0]   /* L1_lo[0] = 0x0 */
    mov  x1, #0x404     /* Valid | AF | SH_Inner | Attr1(Normal) | 0x4000_0000 */
    movk x1, #0x4000, lsl #16
    str  x1, [x0, #8]   /* L1_lo[1] = 0x4000_0000 */

    /* L1_hi (Higher-half @ 0xFFFFFF8000000000)
     * Index 0 in 39-bit VA space.
     */
    adrp x0, l1_hi
    add  x0, x0, #:lo12:l1_hi
    mov  x1, #0x401     /* Valid | AF | SH_Inner | Attr0(Device) | 0x0 */
    str  x1, [x0, #0]   /* L1_hi[0] = 0x0 */
    mov  x1, #0x404     /* Valid | AF | SH_Inner | Attr1(Normal) | 0x4000_0000 */
    movk x1, #0x4000, lsl #16
    str  x1, [x0, #8]   /* L1_hi[1] = 0x4000_0000 */

    /* MAIR_EL1 */
    mov  x0, #0x04FF
    msr  mair_el1, x0

    /* TCR_EL1 */
    mov  x0, #25
    mov  x1, #25
    orr  x0, x0, x1, lsl #16    /* T0SZ | T1SZ */
    mov  x1, #3
    orr  x0, x0, x1, lsl #12    /* SH0 */
    orr  x0, x0, x1, lsl #28    /* SH1 */
    mov  x1, #1
    orr  x0, x0, x1, lsl #10    /* ORGN0 */
    orr  x0, x0, x1, lsl #26    /* ORGN1 */
    orr  x0, x0, x1, lsl #8     /* IRGN0 */
    orr  x0, x0, x1, lsl #24    /* IRGN1 */
    mov  x1, #2
    orr  x0, x0, x1, lsl #30    /* TG1=4KB */
    mov  x1, #2
    orr  x0, x0, x1, lsl #32    /* IPS=40-bit */
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
    orr  x0, x0, #0x1           /* M=1 */
    orr  x0, x0, #0x4           /* C=1 */
    orr  x0, x0, #0x1000        /* I=1 */
    msr  sctlr_el1, x0
    isb

    ldr  x0, =_start_rust_virtual
    br   x0

_start_rust_virtual:
    mov  x0, #0x0000
    movk x0, #0x8000, lsl #32
    movk x0, #0xffff, lsl #48
    add  sp, sp, x0

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
