//! CLDEMOTE / MOVDIRI / MOVDIR64B — cache hints + direct stores.
//!
//! Spec: `arch/specification/cpu-perf-niche.md` §3.
//!
//! All three instructions are CPL-agnostic and silent no-ops on
//! older silicon (CLDEMOTE decodes as NOP; MOVDIRI / MOVDIR64B
//! `#UD` if unsupported, so callers must gate on `*_supported`
//! before issue).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

fn ecx_7_0() -> u32 {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return 0; }
    // SAFETY: leaf 7 valid.
    unsafe { cpuid(7, 0).2 }
}

/// `true` iff CPUID(7, 0).ECX[25] is set.
pub fn cldemote_supported() -> bool { ecx_7_0() & (1 << 25) != 0 }

/// `true` iff CPUID(7, 0).ECX[27] is set.
pub fn movdiri_supported() -> bool { ecx_7_0() & (1 << 27) != 0 }

/// `true` iff CPUID(7, 0).ECX[28] is set.
pub fn movdir64b_supported() -> bool { ecx_7_0() & (1 << 28) != 0 }

/// Demote the line containing `addr` toward LLC. Encodes as a
/// hint — silent no-op on CPUs that don't recognise it, so this
/// is safe to issue unconditionally.
///
/// # Safety
/// `addr` is a valid linear address the caller may load from.
#[inline]
pub unsafe fn cldemote(addr: *const u8) {
    // SAFETY: caller-asserted; CLDEMOTE encoding `0F 1C /0`.
    unsafe {
        core::arch::asm!(
            "cldemote [{a}]",
            a = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// `MOVDIRI [dst], val` — direct 32-bit store, write-combining.
///
/// # Safety
/// `dst` is a valid 4-byte-aligned write target; MOVDIRI
/// supported.
#[inline]
pub unsafe fn movdiri32(dst: *mut u32, val: u32) {
    // SAFETY: caller-asserted; encoding `0F 38 F9`.
    unsafe {
        core::arch::asm!(
            "movdiri [{d}], {v:e}",
            d = in(reg) dst,
            v = in(reg) val,
            options(nostack, preserves_flags),
        );
    }
}

/// `MOVDIRI [dst], val` — direct 64-bit store.
///
/// # Safety
/// As `movdiri32`, with 8-byte alignment.
#[inline]
pub unsafe fn movdiri64(dst: *mut u64, val: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "movdiri [{d}], {v}",
            d = in(reg) dst,
            v = in(reg) val,
            options(nostack, preserves_flags),
        );
    }
}

/// `MOVDIR64B dst, src` — copy 64 bytes from `src` to `dst` as a
/// single atomic store.
///
/// # Safety
/// `dst` is 64-byte-aligned; `src` is readable; MOVDIR64B
/// supported. Tearing-free across the bus is the architectural
/// guarantee — the consumer reading `dst` sees either all-old
/// or all-new contents on a properly-aligned 64-byte read.
#[inline]
pub unsafe fn movdir64b(dst: *mut u8, src: *const u8) {
    // SAFETY: caller-asserted; encoding `66 0F 38 F8`.
    unsafe {
        core::arch::asm!(
            "movdir64b {d}, [{s}]",
            d = in(reg) dst,
            s = in(reg) src,
            options(nostack, preserves_flags),
        );
    }
}
