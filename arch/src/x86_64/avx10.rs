//! AVX10 — converged AVX-512 / AVX2 vector ISA enumeration.
//!
//! Spec: `arch/specification/cpu-perf-niche.md` §5.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, Default)]
pub struct Avx10Caps {
    pub supported: bool,
    pub version: u8,
    pub xmm: bool,
    pub ymm: bool,
    pub zmm: bool,
    pub converged_with_avx512: bool,
}

/// `true` iff CPUID(7, 1).EDX[19] is set (AVX10 enumeration leaf
/// 0x24 present).
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub-leaf 1 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 1) };
    edx & (1 << 19) != 0
}

pub fn caps() -> Avx10Caps {
    let mut caps = Avx10Caps::default();
    if !supported() {
        return caps;
    }
    caps.supported = true;
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x24 {
        return caps;
    }
    // SAFETY: leaf 0x24 valid when supported.
    let (eax, ebx, _, _) = unsafe { cpuid(0x24, 0) };
    caps.version = (eax & 0xFF) as u8;
    caps.xmm = ebx & (1 << 0) != 0 || (ebx & 0xFF) != 0; // XMM always supported
    caps.ymm = ebx & (1 << 8) != 0;
    caps.zmm = ebx & (1 << 9) != 0;
    caps.converged_with_avx512 = ebx & (1 << 16) != 0;
    caps
}
