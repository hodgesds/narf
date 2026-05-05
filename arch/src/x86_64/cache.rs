//! x86_64 cache geometry + line-write/flush instructions.
//!
//! Spec: `arch/specification/cpu-info-errata.md` §2.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, Default)]
pub struct CacheCaps {
    pub clflush:    bool,
    pub clflushopt: bool,
    pub clwb:       bool,
    pub wbnoinvd:   bool,
    pub line_bytes: u16,
}

pub fn caps() -> CacheCaps {
    let mut c = CacheCaps::default();
    // SAFETY: leaf 0 always defined.
    let (max, _, _, _) = unsafe { cpuid(0, 0) };
    if max >= 1 {
        // SAFETY: leaf 1 valid.
        let (_, ebx, _, edx) = unsafe { cpuid(1, 0) };
        c.clflush    = edx & (1 << 19) != 0;
        c.line_bytes = ((ebx >> 8) & 0xFF) as u16 * 8;
    }
    if max >= 7 {
        // SAFETY: leaf 7 valid.
        let (_, ebx, _, _) = unsafe { cpuid(7, 0) };
        c.clflushopt = ebx & (1 << 23) != 0;
        c.clwb       = ebx & (1 << 24) != 0;
    }
    // SAFETY: leaf 0x8000_0000 always defined.
    let (max_ext, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
    if max_ext >= 0x8000_0008 {
        // SAFETY: gated.
        let (_, ebx, _, _) = unsafe { cpuid(0x8000_0008, 0) };
        c.wbnoinvd = ebx & (1 << 9) != 0;
    }
    c
}

/// `CLFLUSH [addr]` — flush the cache line containing `addr`
/// from every level. Strongly serialising w.r.t. older stores.
///
/// # Safety
/// `addr` is a valid linear address; `caps().clflush == true`.
#[inline]
pub unsafe fn clflush(addr: *const u8) {
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "clflush [{a}]",
            a = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// `CLFLUSHOPT [addr]` — same as CLFLUSH but ordered only with
/// respect to fences + stores to the same line. Cheaper for
/// flush-many-lines patterns.
///
/// # Safety
/// `caps().clflushopt == true`.
#[inline]
pub unsafe fn clflushopt(addr: *const u8) {
    // SAFETY: caller-asserted; encoding `66 0F AE /7`.
    unsafe {
        core::arch::asm!(
            "clflushopt [{a}]",
            a = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// `CLWB [addr]` — write-back without invalidate; line stays
/// in the cache hierarchy.
///
/// # Safety
/// `caps().clwb == true`.
#[inline]
pub unsafe fn clwb(addr: *const u8) {
    // SAFETY: caller-asserted; encoding `66 0F AE /6`.
    unsafe {
        core::arch::asm!(
            "clwb [{a}]",
            a = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// `WBNOINVD` — AMD: write back the entire cache hierarchy
/// without invalidating. Use sparingly (architectural broadcast).
///
/// # Safety
/// CPL = 0; `caps().wbnoinvd == true`.
#[inline]
pub unsafe fn wbnoinvd() {
    // SAFETY: caller-asserted; encoding `F3 0F 09`.
    unsafe {
        core::arch::asm!(
            ".byte 0xF3, 0x0F, 0x09",
            options(nostack, preserves_flags),
        );
    }
}
