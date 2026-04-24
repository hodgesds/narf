//! aarch64 system-register helpers.
//!
//! Every accessor carries the `compiler_fence(SeqCst)` pair discipline
//! from `arch/` §4 to defeat fat-LTO reorder across privileged MSR /
//! MRS instructions.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// Write `VBAR_EL1` — the EL1 exception vector table base address.
/// Takes effect immediately; subsequent exceptions dispatch through
/// `addr`.
///
/// # Safety
/// `addr` must be 2 KiB-aligned and point at a 16-entry AArch64
/// exception vector table as laid out by `frame/aarch64/vec.S`.
#[inline]
pub unsafe fn write_vbar_el1(addr: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR VBAR_EL1 at EL1 is legal.
    unsafe {
        asm!("msr vbar_el1, {v}", v = in(reg) addr,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_SRE_EL1` — GICv3 system-register enable.
///
/// # Safety
/// Requires GICv3 sysreg interface exposed (check via CPUID).
#[inline]
pub unsafe fn write_icc_sre_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR ICC_SRE_EL1 at EL1 is legal when GICv3 is present.
    unsafe {
        asm!("msr icc_sre_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_PMR_EL1` — priority mask for CPU-interface IRQs.
///
/// # Safety
/// Requires `ICC_SRE_EL1.SRE = 1` to have been set first.
#[inline]
pub unsafe fn write_icc_pmr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR legal once SRE is enabled.
    unsafe {
        asm!("msr icc_pmr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_IGRPEN1_EL1` — enable Group 1 IRQs.
///
/// # Safety
/// Requires SRE.
#[inline]
pub unsafe fn write_icc_igrpen1_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR legal once SRE is enabled.
    unsafe {
        asm!("msr icc_igrpen1_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read `ICC_IAR1_EL1` — acknowledge the highest-priority pending Group
/// 1 IRQ. Returns the INTID (low 24 bits).
///
/// # Safety
/// Must be called from an IRQ handler; reading clears the IRQ from the
/// CPU interface.
#[inline]
pub unsafe fn read_icc_iar1_el1() -> u64 {
    compiler_fence(Ordering::SeqCst);
    let v: u64;
    // SAFETY: MRS ICC_IAR1_EL1 is the documented handler entry path.
    unsafe {
        asm!("mrs {v}, icc_iar1_el1", v = out(reg) v,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write `ICC_EOIR1_EL1` — end-of-interrupt for Group 1. Pass the
/// value previously read from `ICC_IAR1_EL1`.
///
/// # Safety
/// Must match a prior IAR read, from inside an IRQ handler.
#[inline]
pub unsafe fn write_icc_eoir1_el1(iar: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: EOI to Group 1; matching IAR.
    unsafe {
        asm!("msr icc_eoir1_el1, {v}", v = in(reg) iar,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `CNTP_TVAL_EL0` — sets the physical timer's next-fire count
/// as a delta from now. When written, the timer re-arms.
///
/// # Safety
/// Always legal at EL1.
#[inline]
pub unsafe fn write_cntp_tval_el0(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: CNTP_TVAL_EL0 write is always legal at EL1 / EL0 (when
    // CNTKCTL_EL1 grants EL0 access).
    unsafe {
        asm!("msr cntp_tval_el0, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `CNTP_CTL_EL0` — physical-timer control.
///   bit 0: ENABLE
///   bit 1: IMASK (1 = masked)
///   bit 2: ISTATUS (read-only, set when the timer has fired)
///
/// # Safety
/// Always legal at EL1.
#[inline]
pub unsafe fn write_cntp_ctl_el0(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: see write_cntp_tval_el0.
    unsafe {
        asm!("msr cntp_ctl_el0, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read the saved `ESR_EL1` (exception syndrome) after an exception.
/// Used by synchronous-exception handlers.
///
/// # Safety
/// Always legal at EL1.
#[inline]
pub unsafe fn read_esr_el1() -> u64 {
    let v: u64;
    // SAFETY: MRS ESR_EL1 at EL1 is always legal.
    unsafe {
        asm!("mrs {v}, esr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `FAR_EL1` (fault address register).
#[inline]
pub unsafe fn read_far_el1() -> u64 {
    let v: u64;
    // SAFETY: MRS FAR_EL1 at EL1 is always legal.
    unsafe {
        asm!("mrs {v}, far_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `ELR_EL1` — exception-link register (saved PC at exception entry).
#[inline]
pub unsafe fn read_elr_el1() -> u64 {
    let v: u64;
    // SAFETY: MRS ELR_EL1 at EL1 is always legal.
    unsafe {
        asm!("mrs {v}, elr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `SCTLR_EL1` — System Control Register.
#[inline]
pub unsafe fn read_sctlr_el1() -> u64 {
    let v: u64;
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("mrs {v}, sctlr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `SCTLR_EL1`.
#[inline]
pub unsafe fn write_sctlr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr sctlr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `TCR_EL1` — Translation Control Register.
#[inline]
pub unsafe fn write_tcr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr tcr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read `TCR_EL1`.
#[inline]
pub unsafe fn read_tcr_el1() -> u64 {
    let v: u64;
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("mrs {v}, tcr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `GCR_EL1` — Tag Control Register.
#[inline]
pub unsafe fn write_gcr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr gcr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read `GCR_EL1`.
#[inline]
pub unsafe fn read_gcr_el1() -> u64 {
    let v: u64;
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("mrs {v}, gcr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `MAIR_EL1` — Memory Attribute Indirection Register.
#[inline]
pub unsafe fn write_mair_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr mair_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `TTBR0_EL1` — Translation Table Base Register 0.
#[inline]
pub unsafe fn write_ttbr0_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr ttbr0_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `TTBR1_EL1` — Translation Table Base Register 1.
#[inline]
pub unsafe fn write_ttbr1_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr ttbr1_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate entire TLB for EL1.
#[inline]
pub unsafe fn tlb_flush_all() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: TLBI VMALLE1 is legal at EL1.
    unsafe {
        asm!("tlbi vmalle1", "dsb nsh", "isb",
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate TLB by virtual address for EL1.
#[inline]
pub unsafe fn tlb_flush_page(virt_addr: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: TLBI VAAE1 is legal at EL1. Shifts VA by 12 as required.
    unsafe {
        asm!("tlbi vaae1, {v}", "dsb nsh", "isb",
             v = in(reg) (virt_addr >> 12),
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Instruction Synchronization Barrier.
#[inline]
pub unsafe fn isb() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: ISB is always legal.
    unsafe {
        asm!("isb", options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}


