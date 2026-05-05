//! AMD RDPRU — Read Processor Register at User level.
//!
//! Spec: `arch/specification/cpu-perf-niche.md` §2.
//!
//! `RDPRU` (encoding `0F 01 FD`) reads selected MSRs from
//! CPL = 3 with no syscall round-trip. v0.1 enumerates ECX = 0
//! (MPERF) and ECX = 1 (APERF) — sufficient for userspace
//! frequency-tracking heuristics.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr;

const MSR_MPERF: u32 = 0x000000E7;
const MSR_APERF: u32 = 0x000000E8;

/// `true` iff CPUID(0x8000_0008).EBX[4] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0x8000_0000 always defined.
    let max = unsafe { cpuid(0x8000_0000, 0).0 };
    if max < 0x8000_0008 { return false; }
    // SAFETY: leaf 0x8000_0008 valid.
    let (_, ebx, _, _) = unsafe { cpuid(0x8000_0008, 0) };
    ebx & (1 << 4) != 0
}

/// Issue `RDPRU` for `reg`. Returns `EDX:EAX`.
///
/// # Safety
/// `reg` is one of the architecturally-defined values
/// (currently 0 = MPERF, 1 = APERF). RDPRU is safe at any CPL
/// when supported; using it without prior `supported()` results
/// in `#UD`.
#[inline]
pub unsafe fn rdpru(reg: u32) -> u64 {
    let eax: u32;
    let edx: u32;
    // SAFETY: caller-asserted; encoding `0F 01 FD`.
    unsafe {
        core::arch::asm!(
            ".byte 0x0F, 0x01, 0xFD",
            in("ecx") reg,
            out("eax") eax,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    ((edx as u64) << 32) | (eax as u64)
}

/// Read MPERF. Uses RDPRU when supported, falls back to RDMSR.
///
/// # Safety
/// CPL = 0 (for the RDMSR fallback); RDPRU path is CPL-agnostic.
pub unsafe fn read_mperf() -> u64 {
    if supported() {
        // SAFETY: gated.
        unsafe { rdpru(0) }
    } else {
        // SAFETY: caller-asserted.
        unsafe { rdmsr(MSR_MPERF) }
    }
}

/// Read APERF.
///
/// # Safety
/// Same as `read_mperf`.
pub unsafe fn read_aperf() -> u64 {
    if supported() {
        // SAFETY: gated.
        unsafe { rdpru(1) }
    } else {
        // SAFETY: caller-asserted.
        unsafe { rdmsr(MSR_APERF) }
    }
}
