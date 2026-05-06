//! Intel LAM — Linear Address Masking.
//!
//! Spec: `arch/specification/cpu-security.md` §4.
//!
//! Sapphire Rapids+. LAM lets userspace store metadata in the
//! upper bits of a pointer without violating the canonical-form
//! check on memory accesses — the CPU masks the metadata away
//! before address translation. Two user modes: LAM_U48 (top 6
//! bits ignored, 48-bit canonical) and LAM_U57 (top 6 bits of a
//! 57-bit canonical address ignored). Supervisor-side LAM is
//! gated independently by CR4.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

const CR3_LAM_U48: u64 = 1 << 62;
const CR3_LAM_U57: u64 = 1 << 61;
const CR4_LAM_SUP: u64 = 1 << 28;

/// `true` iff CPUID(7, 1).EAX[26] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub-leaf 1 defined.
    let (eax, _, _, _) = unsafe { cpuid(7, 1) };
    eax & (1 << 26) != 0
}

#[inline]
unsafe fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: CR3 readable at CPL=0.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline]
unsafe fn write_cr3(v: u64) {
    // SAFETY: caller-asserted CPL=0.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) v, options(nomem, nostack));
    }
}

#[inline]
unsafe fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: CR4 readable at CPL=0.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline]
unsafe fn write_cr4(v: u64) {
    // SAFETY: caller-asserted CPL=0.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) v, options(nomem, nostack));
    }
}

/// Enable user-mode LAM with 48-bit canonical form.
///
/// # Safety
/// CPL = 0; LAM supported.
pub unsafe fn enable_user_lam_u48() {
    // SAFETY: caller-asserted.
    let cur = unsafe { read_cr3() };
    let v = (cur & !CR3_LAM_U57) | CR3_LAM_U48;
    // SAFETY: same.
    unsafe {
        write_cr3(v);
    }
}

/// Enable user-mode LAM with 57-bit canonical form.
///
/// # Safety
/// CPL = 0; LAM + 5-level paging supported.
pub unsafe fn enable_user_lam_u57() {
    // SAFETY: caller-asserted.
    let cur = unsafe { read_cr3() };
    let v = (cur & !CR3_LAM_U48) | CR3_LAM_U57;
    // SAFETY: same.
    unsafe {
        write_cr3(v);
    }
}

/// Enable supervisor LAM (CR4.LAM_SUP).
///
/// # Safety
/// CPL = 0; LAM supported.
pub unsafe fn enable_supervisor_lam() {
    // SAFETY: caller-asserted.
    let cur = unsafe { read_cr4() };
    // SAFETY: same.
    unsafe {
        write_cr4(cur | CR4_LAM_SUP);
    }
}

/// Disable both LAM_U48 + LAM_U57 in CR3.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_user_lam() {
    // SAFETY: caller-asserted.
    let cur = unsafe { read_cr3() };
    // SAFETY: same.
    unsafe {
        write_cr3(cur & !(CR3_LAM_U48 | CR3_LAM_U57));
    }
}
