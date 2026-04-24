/*
 * EL1 exception vector table for aarch64.
 *
 * AArch64 requires a single 2 KiB-aligned table of 16 entries, each
 * 128 bytes (32 instructions). The table covers 4 exception classes
 * × 4 sources:
 *
 *   Source                 Sync     IRQ      FIQ      SError
 *   ──────────────────────────────────────────────────────────────
 *   Current EL, SP_EL0      0        1        2        3        (offsets 0x000, 0x080, 0x100, 0x180)
 *   Current EL, SP_ELx      4        5        6        7        (offsets 0x200, 0x280, 0x300, 0x380)
 *   Lower EL, AArch64       8        9       10       11        (offsets 0x400, 0x480, 0x500, 0x580)
 *   Lower EL, AArch32      12       13       14       15        (offsets 0x600, 0x680, 0x700, 0x780)
 *
 * Stage-2 uses entry 5 (IRQ from current EL, using SP_ELx) — that's
 * the one QEMU delivers when an IRQ arrives while the kernel is
 * executing on its own stack. Everything else either stubs to a
 * sync-fault handler that panics or is unreachable in our single-EL
 * configuration.
 */

.section .text
.align 11                  /* 2 KiB alignment */
.global __narf_vector_table
.type   __narf_vector_table, @function
__narf_vector_table:

    /* ─── Current EL, SP_EL0 (offsets 0x000 .. 0x180) ────── */
    .align 7                /* 128-byte slot */
    b       __narf_vec_sync_sp0        /* 0x000 — synchronous */
    .align 7
    b       __narf_vec_irq             /* 0x080 — IRQ (rare at EL1/SP0 but route) */
    .align 7
    b       __narf_vec_unimpl          /* 0x100 — FIQ */
    .align 7
    b       __narf_vec_serror          /* 0x180 — SError */

    /* ─── Current EL, SP_ELx (0x200 .. 0x380) ─── main case */
    .align 7
    b       __narf_vec_sync_spx        /* 0x200 — synchronous */
    .align 7
    b       __narf_vec_irq             /* 0x280 — IRQ ← the one */
    .align 7
    b       __narf_vec_unimpl          /* 0x300 — FIQ */
    .align 7
    b       __narf_vec_serror          /* 0x380 — SError */

    /* ─── Lower EL, AArch64 (0x400 .. 0x580) ─── unreachable today */
    .align 7
    b       __narf_vec_unimpl
    .align 7
    b       __narf_vec_unimpl
    .align 7
    b       __narf_vec_unimpl
    .align 7
    b       __narf_vec_unimpl

    /* ─── Lower EL, AArch32 (0x600 .. 0x780) ─── unreachable */
    .align 7
    b       __narf_vec_unimpl
    .align 7
    b       __narf_vec_unimpl
    .align 7
    b       __narf_vec_unimpl
    .align 7
    b       __narf_vec_unimpl

.size __narf_vector_table, . - __narf_vector_table

/* ──────────────────────────────────────────────────────────────
 * Save all 31 GPRs on the current stack. Returns with x0 = frame
 * pointer (= current SP). Assumes entry from the vector table, so
 * nothing has been pushed yet.
 *
 * Register save order (16 stp pairs, stack grows down 16 bytes each):
 *   sp-16:  x30, xzr
 *   sp-32:  x28, x29
 *   sp-48:  x26, x27
 *   ...
 *   sp-256: x0, x1      ← last push, so frame[0] = x0 at offset 0
 *
 * With SP-relative offsets from the final SP (what Rust sees):
 *   [sp +   0] = x0
 *   [sp +   8] = x1
 *   ...
 *   [sp + 232] = x29
 *   [sp + 240] = x30
 *   [sp + 248] = saved zero-slot (unused)
 * ────────────────────────────────────────────────────────────── */
.macro SAVE_ALL_GPRS
    stp     x28, x29, [sp, #-16]!
    stp     x26, x27, [sp, #-16]!
    stp     x24, x25, [sp, #-16]!
    stp     x22, x23, [sp, #-16]!
    stp     x20, x21, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x8,  x9,  [sp, #-16]!
    stp     x6,  x7,  [sp, #-16]!
    stp     x4,  x5,  [sp, #-16]!
    stp     x2,  x3,  [sp, #-16]!
    stp     x0,  x1,  [sp, #-16]!
    /* And x30 (LR) separately, plus ELR/SPSR so the return path has
     * them. Put x30 on first, then ELR/SPSR pair. */
    str     x30,      [sp, #-16]!
.endm

.macro RESTORE_ALL_GPRS
    ldr     x30,      [sp], #16
    ldp     x0,  x1,  [sp], #16
    ldp     x2,  x3,  [sp], #16
    ldp     x4,  x5,  [sp], #16
    ldp     x6,  x7,  [sp], #16
    ldp     x8,  x9,  [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x18, x19, [sp], #16
    ldp     x20, x21, [sp], #16
    ldp     x22, x23, [sp], #16
    ldp     x24, x25, [sp], #16
    ldp     x26, x27, [sp], #16
    ldp     x28, x29, [sp], #16
.endm

.align 4
.type __narf_vec_irq, @function
__narf_vec_irq:
    SAVE_ALL_GPRS
    mov     x0, sp
    bl      rust_aarch64_irq
    RESTORE_ALL_GPRS
    eret
.size __narf_vec_irq, . - __narf_vec_irq

.align 4
.type __narf_vec_sync_spx, @function
__narf_vec_sync_spx:
    SAVE_ALL_GPRS
    mov     x0, sp
    bl      rust_aarch64_sync_dispatch
    /* For SVC-class sync exceptions the dispatcher writes the
     * return value into the saved x0 slot and returns here;
     * RESTORE_ALL_GPRS + eret resumes user state. Fatal sync
     * exceptions (page-fault etc) call exit_kernel from Rust and
     * never return. */
    RESTORE_ALL_GPRS
    eret
.size __narf_vec_sync_spx, . - __narf_vec_sync_spx

.align 4
.type __narf_vec_sync_sp0, @function
__narf_vec_sync_sp0:
    SAVE_ALL_GPRS
    mov     x0, sp
    bl      rust_aarch64_sync_sp0
1:  wfe
    b       1b
.size __narf_vec_sync_sp0, . - __narf_vec_sync_sp0

.align 4
.type __narf_vec_serror, @function
__narf_vec_serror:
    SAVE_ALL_GPRS
    mov     x0, sp
    bl      rust_aarch64_serror
1:  wfe
    b       1b
.size __narf_vec_serror, . - __narf_vec_serror

.align 4
.type __narf_vec_unimpl, @function
__narf_vec_unimpl:
    SAVE_ALL_GPRS
    mov     x0, sp
    bl      rust_aarch64_unimpl
1:  wfe
    b       1b
.size __narf_vec_unimpl, . - __narf_vec_unimpl
