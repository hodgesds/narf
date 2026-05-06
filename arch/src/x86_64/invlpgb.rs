//! AMD INVLPGB / TLBSYNC — broadcast TLB invalidation.
//!
//! Spec: `arch/specification/cpu-perf-niche.md` §1.
//!
//! INVLPGB issues a TLB-invalidation request that fans out
//! across the CCX without an IPI. TLBSYNC blocks until the
//! local CPU's outstanding INVLPGBs have drained on every
//! CPU in the broadcast domain.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

/// `RAX` flag: VA in upper bits is meaningful.
pub const INVLPGB_VA_VALID: u64 = 1 << 0;
/// `RAX` flag: ASID/PCID field in `ECX[31:16]` is meaningful.
pub const INVLPGB_PCID_VALID: u64 = 1 << 1;
/// `RAX` flag: also invalidate global pages.
pub const INVLPGB_INCLUDE_GLOBAL: u64 = 1 << 2;
/// `RAX` flag: only final-level translations.
pub const INVLPGB_FINAL_ONLY: u64 = 1 << 3;
/// `RAX` flag: nested (treat as guest TLB).
pub const INVLPGB_NESTED: u64 = 1 << 4;

/// `true` iff CPUID(0x8000_0008).EBX[3] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0x8000_0000 always defined.
    let max = unsafe { cpuid(0x8000_0000, 0).0 };
    if max < 0x8000_0008 {
        return false;
    }
    // SAFETY: leaf 0x8000_0008 valid.
    let (_, ebx, _, _) = unsafe { cpuid(0x8000_0008, 0) };
    ebx & (1 << 3) != 0
}

/// Maximum number of pages addressable by a single INVLPGB —
/// `CPUID(0x8000_0008).EAX[15:0]`.
pub fn count_max() -> u16 {
    if !supported() {
        return 0;
    }
    // SAFETY: gated.
    let (eax, _, _, _) = unsafe { cpuid(0x8000_0008, 0) };
    eax as u16
}

/// Maximum ASID INVLPGB can target — `CPUID(0x8000_0008).EBX[31:16]`.
pub fn asid_max() -> u16 {
    if !supported() {
        return 0;
    }
    // SAFETY: gated.
    let (_, ebx, _, _) = unsafe { cpuid(0x8000_0008, 0) };
    (ebx >> 16) as u16
}

/// Raw INVLPGB. `rax` carries flag-bits + (when `VA_VALID`)
/// the start address; `ecx[15:0]` is the count of additional
/// pages, `ecx[31:16]` the ASID, `edx[15:0]` the PCID.
///
/// # Safety
/// CPL = 0; INVLPGB supported; the addressed range is currently
/// mapped or the caller has ensured no concurrent walker will
/// trip.
#[inline]
pub unsafe fn invlpgb(rax: u64, ecx: u32, edx: u32) {
    // SAFETY: caller-asserted. Encoding `0F 01 FE`.
    unsafe {
        core::arch::asm!(
            ".byte 0x0F, 0x01, 0xFE",
            in("rax") rax,
            in("ecx") ecx,
            in("edx") edx,
            options(nostack, preserves_flags),
        );
    }
}

/// Block until this CPU's outstanding INVLPGBs have drained.
///
/// # Safety
/// CPL = 0; INVLPGB supported.
#[inline]
pub unsafe fn tlbsync() {
    // SAFETY: caller-asserted. Encoding `0F 01 FF`.
    unsafe {
        core::arch::asm!(".byte 0x0F, 0x01, 0xFF", options(nostack, preserves_flags),);
    }
}

/// Broadcast invalidation of every global page on every CPU in
/// the home node. Followed by `tlbsync` for completion.
///
/// # Safety
/// CPL = 0; INVLPGB supported.
pub unsafe fn invalidate_all_global() {
    // SAFETY: caller-asserted.
    unsafe {
        invlpgb(INVLPGB_INCLUDE_GLOBAL, 0, 0);
        tlbsync();
    }
}

/// Broadcast invalidation of every entry tagged with `asid`.
/// Followed by `tlbsync` for completion.
///
/// # Safety
/// CPL = 0; INVLPGB supported; `asid` fits in `asid_max()`.
pub unsafe fn invalidate_asid(asid: u16) {
    let ecx = (asid as u32) << 16;
    // SAFETY: caller-asserted.
    unsafe {
        invlpgb(INVLPGB_PCID_VALID, ecx, 0);
        tlbsync();
    }
}
