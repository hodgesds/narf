//! CET — Control-flow Enforcement Technology.
//!
//! Spec: `arch/specification/security-hardening.md` §1.
//!
//! Two independent components:
//!
//!   - **Shadow stack** (CPUID(7, 0).ECX[7]): hardware-enforced
//!     return-address shadow stored in a separate page-table-protected
//!     region. Mismatches between the regular RSP-relative return
//!     and the shadow `IA32_PL{0..3}_SSP` raise `#CP`.
//!   - **IBT** (CPUID(7, 0).EDX[20]): every indirect branch must
//!     land on an `endbr64` (or `endbr32`) instruction; otherwise
//!     `#CP` (control-protection fault).
//!
//! Stage cut: detection + per-ring enable. Per-task shadow stack
//! switching at context-switch is `frame/`'s job and lands separately.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_U_CET:                u32 = 0x6A0;
pub const MSR_IA32_S_CET:                u32 = 0x6A2;
pub const MSR_IA32_PL0_SSP:              u32 = 0x6A4;
pub const MSR_IA32_PL3_SSP:              u32 = 0x6A7;
pub const MSR_IA32_INTERRUPT_SSP_TABLE:  u32 = 0x6A8;

const SH_STK_EN:    u64 = 1 << 0;
const WR_SHSTK_EN:  u64 = 1 << 1;
const ENDBR_EN:     u64 = 1 << 2;
const NO_TRACK_EN:  u64 = 1 << 4;

const CR4_CET: u64 = 1 << 23;

#[derive(Copy, Clone, Debug, Default)]
pub struct CetCaps {
    pub shadow_stack: bool,
    pub ibt:          bool,
    pub cr4_cet:      bool,
}

pub fn caps() -> CetCaps {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return CetCaps::default(); }
    // SAFETY: leaf 7 valid.
    let (_, _, ecx, edx) = unsafe { cpuid(7, 0) };
    // SAFETY: CR4 read at CPL=0 is always defined; the result
    // shape is just informational here.
    let cr4 = read_cr4();
    CetCaps {
        shadow_stack: ecx & (1 << 7) != 0,
        ibt:          edx & (1 << 20) != 0,
        cr4_cet:      cr4 & CR4_CET != 0,
    }
}

#[inline]
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: CR4 is always readable at CPL=0.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline]
unsafe fn write_cr4(v: u64) {
    // SAFETY: caller-asserted CPL=0; writing CR4 is architecturally
    // legal but careful: enabling reserved bits faults. We only
    // OR in CR4_CET so this is benign.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) v, options(nomem, nostack));
    }
}

/// Enable CET globally (sets CR4.CET if not already on).
///
/// # Safety
/// CPL = 0; CET is supported in CPUID.
pub unsafe fn enable_cr4() {
    let cur = read_cr4();
    if cur & CR4_CET == 0 {
        // SAFETY: caller-asserted; reserved CR4 bits preserved.
        unsafe { write_cr4(cur | CR4_CET); }
    }
}

/// Configure supervisor-side (CPL=0) CET. `shadow_stack` enables
/// shadow-stack enforcement for kernel code; `ibt` enables IBT.
///
/// # Safety
/// CPL = 0; `enable_cr4` has been called.
pub unsafe fn enable_supervisor(shadow_stack: bool, ibt: bool) {
    let mut v = 0u64;
    if shadow_stack { v |= SH_STK_EN | WR_SHSTK_EN; }
    if ibt          { v |= ENDBR_EN | NO_TRACK_EN; }
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_S_CET, v); }
}

/// Configure user-side (CPL=3) CET. Same shape as supervisor.
///
/// # Safety
/// CPL = 0; `enable_cr4` has been called.
pub unsafe fn enable_user(shadow_stack: bool, ibt: bool) {
    let mut v = 0u64;
    if shadow_stack { v |= SH_STK_EN | WR_SHSTK_EN; }
    if ibt          { v |= ENDBR_EN | NO_TRACK_EN; }
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_U_CET, v); }
}

/// Disable CET via CR4.CET clear (the `IA32_*_CET` MSRs are
/// preserved). Useful for unit-test reset paths.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_cr4() {
    let cur = read_cr4();
    if cur & CR4_CET != 0 {
        // SAFETY: caller-asserted.
        unsafe { write_cr4(cur & !CR4_CET); }
    }
}

/// Read the CPL=0 shadow-stack pointer.
///
/// # Safety
/// CPL = 0; CET shadow-stack supported.
pub unsafe fn read_pl0_ssp() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_PL0_SSP) }
}

/// Set the CPL=0 shadow-stack pointer.
///
/// # Safety
/// CPL = 0; the address points at a valid shadow-stack page
/// (PTE-marked Shadow Stack via `Dirty=1, Writable=0`).
pub unsafe fn write_pl0_ssp(addr: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_PL0_SSP, addr); }
}
