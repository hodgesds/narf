//! aarch64 SSBS — Speculative Store Bypass Safe.
//!
//! Spec: `arch/specification/cpu-security.md` §3.
//!
//! Mirrors x86_64 SSBD (`IA32_SPEC_CTRL.SSBD`). When SSBS is set,
//! the CPU forbids speculative load-after-store reordering that
//! could otherwise leak via Spectre-v4.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

fn id_aa64pfr1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64PFR1_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64PFR1_EL1.SSBS` field (bits[7:4]).
///
/// | value | meaning |
/// |-------|---------|
/// | 0     | SSBS not present |
/// | 1     | PSTATE.SSBS controllable via MSR |
/// | 2     | + dedicated `MSR SSBS` instruction |
pub fn caps() -> u8 {
    ((id_aa64pfr1() >> 4) & 0xF) as u8
}

/// Enable the mitigation by clearing PSTATE.SSBS.
///
/// Arm's polarity is intentionally counterintuitive: SSBS=0 forbids
/// exploitable speculative store bypass; SSBS=1 permits it.
///
/// Uses `.inst` raw encoding so the assembler doesn't need
/// `+ssbs` target-feature awareness. Per Arm ARM C5.2.18,
/// `MSR SSBS, #imm` encodes as
///   `0xD503_403F | ((imm & 1) << 8)`
/// for the immediate form.
///
/// # Safety
/// EL1; SSBS supported (`caps() >= 2` for the immediate-form
/// MSR instruction).
pub unsafe fn enable() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted EL1; raw encoding for `MSR SSBS, #0`.
    // ISB is conservative coverage for cores affected by stale-SSBS errata.
    unsafe {
        asm!(".inst 0xD503403F", "isb", options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Disable the mitigation by setting PSTATE.SSBS (permit bypass).
///
/// # Safety
/// Same as `enable`.
pub unsafe fn disable() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted; raw encoding for `MSR SSBS, #1`.
    unsafe {
        asm!(".inst 0xD503413F", "isb", options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read PSTATE.SSBS through the architectural SSBS system register.
///
/// # Safety
/// EL1; `caps() >= 2`.
pub unsafe fn is_enabled() -> bool {
    let raw: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted; raw encoding for `MRS X0, SSBS`.
    unsafe {
        asm!(".inst 0xD53B42C0", lateout("x0") raw, options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    raw & 1 == 0
}
