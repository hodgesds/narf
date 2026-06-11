//! aarch64 SPE — Statistical Profiling Extension.
//!
//! Spec: `arch/specification/cpu-arch-extensions.md` §1.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64dfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64DFR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64dfr0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64DFR0_EL1.PMSVer` field (bits[35:32]).
pub fn caps() -> u8 {
    ((id_aa64dfr0() >> 32) & 0xF) as u8
}

/// `PMSIDR_EL1` (raw `S3_0_C9_C9_7`).
///
/// # Safety
/// EL1; SPE supported (`caps() >= 1`).
pub unsafe fn read_pmsidr() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C9_C9_7", out(reg) v, options(nomem, nostack));
    }
    v
}

/// `PMSCR_EL1` (raw `S3_0_C9_C9_0`).
///
/// # Safety
/// EL1; SPE supported.
pub unsafe fn write_pmscr(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C9_C9_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// `PMSIRR_EL1` (raw `S3_0_C9_C9_3`) — sampling interval reload.
///
/// # Safety
/// EL1; SPE supported.
pub unsafe fn write_interval(period: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C9_C9_3, {}",
            in(reg) period,
            options(nostack, preserves_flags),
        );
    }
}

/// Program the profiling buffer base + limit. `base` must be
/// page-aligned; `limit` is the inclusive byte limit.
///
/// # Safety
/// EL1; SPE supported; the buffer covers `limit - base + 1`
/// bytes of writable contiguous memory.
pub unsafe fn program_buffer(base: u64, limit: u64) {
    // SAFETY: caller-asserted. PMBPTR_EL1 = S3_0_C9_C10_1.
    unsafe {
        asm!("msr S3_0_C9_C10_1, {}", in(reg) base, options(nostack, preserves_flags));
    }
    // SAFETY: caller-asserted. PMBLIMITR_EL1 = S3_0_C9_C10_0;
    // bit 0 is the enable, low 12 bits are reserved/control.
    unsafe {
        asm!("msr S3_0_C9_C10_0, {}", in(reg) (limit & !0xFFF), options(nostack, preserves_flags));
    }
}

const PMBLIMITR_E: u64 = 1 << 0;

fn read_pmblimitr() -> u64 {
    let v: u64;
    // SAFETY: PMBLIMITR readable when SPE present.
    unsafe {
        asm!("mrs {}, S3_0_C9_C10_0", out(reg) v, options(nomem, nostack));
    }
    v
}

fn write_pmblimitr(v: u64) {
    // SAFETY: PMBLIMITR writable at EL1 when SPE present.
    unsafe {
        asm!(
            "msr S3_0_C9_C10_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Enable SPE buffer writes (`PMBLIMITR.E`).
///
/// # Safety
/// EL1; SPE supported; `program_buffer` called previously.
pub unsafe fn enable() {
    write_pmblimitr(read_pmblimitr() | PMBLIMITR_E);
}

/// Disable SPE buffer writes by clearing `PMBLIMITR.E`.
///
/// # Safety
/// EL1; SPE supported.
pub unsafe fn disable() {
    write_pmblimitr(read_pmblimitr() & !PMBLIMITR_E);
}
