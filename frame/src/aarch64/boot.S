/*
 * NARF aarch64 boot stub.
 *
 * Entry contract (U-Boot / QEMU -kernel on virt):
 *   - EL1, little-endian, MMU off.
 *   - X0 = physical address of the DTB.
 *   - X1-X3 reserved (Linux ARM boot protocol).
 *
 * We:
 *   1. Set up a 64 KiB stack in .bss.
 *   2. Construct a RawBootInfo in registers: X0 = DTB magic, X1 = X0 (payload).
 *   3. Call _start_rust(magic, payload).
 *
 * MMU enable and `console::remap_to_virtual` are Wave 2's responsibility.
 */

.section .boot, "ax"
.global _start
.type _start, @function
_start:
    /* Save the incoming DTB pointer before we clobber X0. */
    mov x19, x0

    /* Stack in .bss. AAPCS64 requires SP 16-byte aligned. */
    adrp x0, stack_top
    add  x0, x0, #:lo12:stack_top
    mov  sp, x0

    /* Build _start_rust's args:
     *   x0 = magic  = 0xd00dfeed (FDT canonical magic, big-endian on wire
     *                 but stored in the register as the host-native value
     *                 after we'll do to_be() when validating).
     *   x1 = payload = DTB phys address (saved in x19).
     */
    mov x0, #0xfeed
    movk x0, #0xd00d, lsl #16
    mov x1, x19

    bl  _start_rust

    /* _start_rust is -> !; if it ever returns, halt. */
1:  wfi
    b 1b
.size _start, . - _start

.section .bss
.align 4
stack_bottom:
    .skip 4096 * 16
stack_top:
