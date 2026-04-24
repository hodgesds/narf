//! aarch64 feature detection via `ID_AA64*_EL1` system registers.
//!
//! Structurally mirrors `x86_64::cpuid::Features`. x86_64 calls its
//! detection path "CPUID" after the instruction; aarch64 reads ID
//! system registers instead. Keeping the module name `cpuid` on both
//! sides lets arch-agnostic frame/ code write
//! `narf_arch::current::Features::probe()` without cfg branches.

use core::arch::asm;

/// Feature snapshot. Stage-2 fields only; rich aarch64 feature set
/// lands as needed.
#[derive(Copy, Clone, Debug, Default)]
pub struct Features {
    /// MTE support level from `ID_AA64PFR1_EL1.MTE` (bits 11:8).
    ///   0 = none; 1 = MTE instructions; 2 = MTE check (E0PD etc.);
    ///   3 = asymmetric (mte_frac extended).
    pub mte: u8,
    /// Pointer Authentication. `ID_AA64ISAR1_EL1.APA|API` non-zero.
    pub pauth: bool,
    /// BTI — Branch Target Identification (`ID_AA64PFR1_EL1.BT`).
    pub bti: bool,
    /// Generic Timer counter frequency readable via CNTFRQ_EL0.
    /// Always true on ARMv8+; kept for structural parity with x86_64.
    pub generic_timer: bool,
    /// GICv3 system-register interface (`ID_AA64PFR0_EL1.GIC`).
    pub gicv3_sysreg: bool,
}

impl Features {
    /// Probe the ID registers.
    ///
    /// # Safety
    /// `MRS` on ID_AA64*_EL1 is legal at EL1 in long mode; reads are
    /// side-effect-free. Marked `unsafe` for the inline-asm boundary.
    pub unsafe fn probe() -> Self {
        let mut f = Features::default();

        // ID_AA64PFR0_EL1: bits 24:27 = GIC.
        let pfr0 = read_id_aa64pfr0();
        f.gicv3_sysreg = ((pfr0 >> 24) & 0xF) != 0;

        // ID_AA64PFR1_EL1: bits 8:11 = MTE level. bits 0:3 = BT.
        let pfr1 = read_id_aa64pfr1();
        f.mte = ((pfr1 >> 8) & 0xF) as u8;
        f.bti = (pfr1 & 0xF) != 0;

        // ID_AA64ISAR1_EL1: bits 4:7 (APA) or 8:11 (API) non-zero = PAuth.
        let isar1 = read_id_aa64isar1();
        f.pauth = ((isar1 >> 4) & 0xF) != 0 || ((isar1 >> 8) & 0xF) != 0;

        f.generic_timer = true;  // ARMv8+ always provides CNTPCT/CNTFRQ.
        f
    }
}

#[inline]
fn read_id_aa64pfr0() -> u64 {
    let v: u64;
    // SAFETY: reads ID_AA64PFR0_EL1; no side effects, always legal at EL1.
    unsafe {
        asm!("mrs {v}, ID_AA64PFR0_EL1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_id_aa64pfr1() -> u64 {
    let v: u64;
    // SAFETY: reads ID_AA64PFR1_EL1; no side effects, always legal at EL1.
    unsafe {
        asm!("mrs {v}, ID_AA64PFR1_EL1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_id_aa64isar1() -> u64 {
    let v: u64;
    // SAFETY: reads ID_AA64ISAR1_EL1; no side effects.
    unsafe {
        asm!("mrs {v}, ID_AA64ISAR1_EL1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read the generic-timer frequency from CNTFRQ_EL0 (Hz).
///
/// # Safety
/// Reading CNTFRQ_EL0 is always legal.
pub unsafe fn generic_timer_hz() -> u64 {
    let v: u64;
    // SAFETY: CNTFRQ_EL0 is always readable at EL1/EL0.
    unsafe {
        asm!("mrs {v}, CNTFRQ_EL0", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}
