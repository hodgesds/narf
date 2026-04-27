/*
 * NARF aarch64 AP entry stub.
 *
 * Each AP enters here from PSCI CPU_ON with:
 *   x0 = context id (logical CPU id encoded by the BSP)
 *   PC = phys address of `_ap_start`
 *   MMU off, IRQs masked, GIC unconfigured.
 *
 * The trampoline:
 *   1. Loads the per-CPU stack from AP_STACKS[x0].
 *   2. Replays the BSP's MMU bring-up using the same lo_L0/hi_L0
 *      tables boot.S populated.
 *   3. Enables the MMU and branches to a virtual-address Rust
 *      entry point — `_ap_start_rust(logical_id)`.
 */

.section .boot, "ax"

.global _ap_start
.type _ap_start, @function
_ap_start:
    /* Save logical CPU id (passed in x0 by PSCI as context id). */
    mov  x19, x0

    /* Enable FP/SIMD at EL1 (CPACR_EL1.FPEN). Without this Rust's
     * SIMD-emitting code traps. Mirrors boot.S. */
    mrs  x0, cpacr_el1
    orr  x0, x0, #(3 << 20)
    msr  cpacr_el1, x0
    isb

    /* Enable Allocation Tag Access (SCTLR_EL1.ATA) so MTE
     * sysregs are reachable on capable cores. */
    mrs  x0, sctlr_el1
    orr  x0, x0, #(1 << 43)
    msr  sctlr_el1, x0
    isb

    /* Compute per-CPU stack base from AP_STACKS[logical_id].
     * Each entry is 8 bytes (a u64 holding the stack-top
     * physical address). */
    adrp x0, AP_STACKS
    add  x0, x0, #:lo12:AP_STACKS
    ldr  x1, [x0, x19, lsl #3]   /* x1 = stack_top phys */
    mov  sp, x1

    /* MAIR / TCR / TTBR0 / TTBR1 — same setup as the BSP, using
     * the page tables BSP already populated. */
    mov  x0, #0xFF04
    msr  mair_el1, x0

    mov  x0, #16
    orr  x0, x0, #(16 << 16)
    orr  x0, x0, #(3 << 12)
    orr  x0, x0, #(3 << 28)
    orr  x0, x0, #(1 << 10)
    orr  x0, x0, #(1 << 26)
    orr  x0, x0, #(1 << 8)
    orr  x0, x0, #(1 << 24)
    orr  x0, x0, #(2 << 30)
    mov  x1, #2
    orr  x0, x0, x1, lsl #32
    msr  tcr_el1, x0
    isb

    adrp x0, l0_lo
    add  x0, x0, #:lo12:l0_lo
    msr  ttbr0_el1, x0
    adrp x0, l0_hi
    add  x0, x0, #:lo12:l0_hi
    msr  ttbr1_el1, x0

    ic   ialluis
    dsb  sy
    isb

    /* Enable MMU. */
    mrs  x0, sctlr_el1
    orr  x0, x0, #0x1
    orr  x0, x0, #0x1000
    msr  sctlr_el1, x0
    dsb  sy
    isb

    /* Jump to virtual entry. The stack pointer set above is a
     * physical address inside lo_L1[1]'s identity map, so it
     * stays valid post-MMU. We pass logical_id in x0 per AAPCS64. */
    mov  x0, x19
    ldr  x1, =_ap_start_rust
    br   x1

.size _ap_start, . - _ap_start

/* Per-CPU stack-top table. Populated by Rust (smp::reserve_ap_stacks)
 * before psci::cpu_on is issued for the corresponding AP. One u64
 * (stack-top phys) per CPU; index = logical_id; index 0 (BSP) is
 * unused but kept for indexing simplicity. */
.section .boot.data, "aw"
.align 8
.global AP_STACKS
AP_STACKS:
    .skip 8 * 64    /* MAX_CPUS u64 entries */
