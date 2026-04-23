//! CPUID feature detection.
//!
//! Stage 2 uses this to probe for PKS, UIPI, NX, and a handful of
//! related features before enabling the corresponding MSR / CR bits.
//! The spec (`arch/` §4) is clear that required features fail boot
//! and optional features degrade to fallbacks — this module provides
//! the raw queries; policy lives in `frame/`.

use core::arch::asm;

/// Raw CPUID leaf read: returns (eax, ebx, ecx, edx).
///
/// # Safety
/// `CPUID` is legal at CPL=0 for any leaf; invalid leaves return
/// zeros in all four output registers rather than faulting. Safe
/// in any context but marked `unsafe` for consistency with the
/// rest of `arch/`'s privileged-instruction wrappers.
#[inline]
pub unsafe fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (a, c, d): (u32, u32, u32);
    let b: u64;
    // LLVM reserves rbx; the conventional workaround is to save it
    // around CPUID via push/pop and move the result into a scratch
    // register that Rust can see.
    // SAFETY: CPUID is always legal at CPL=0; we preserve rbx.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {b:r}, rbx",
            "pop rbx",
            inout("eax") leaf => a,
            inout("ecx") sub  => c,
            out("edx") d,
            b = out(reg) b,
            options(nostack, preserves_flags),
        );
    }
    (a, b as u32, c, d)
}

/// CPU-feature flags we care about during Stage 1–2 bring-up. Each
/// flag has a `has_*` accessor rather than a single `FeatureFlags`
/// bitset because the sources (multiple CPUID leaves) don't all live
/// in the same register.
#[derive(Copy, Clone, Debug, Default)]
pub struct Features {
    pub nx:       bool,   // leaf 80000001h EDX:20 — NX page bit
    pub pku:      bool,   // leaf 7, sub 0 ECX:3  — user-mode protection keys
    pub pks:      bool,   // leaf 7, sub 0 ECX:31 — supervisor protection keys
    pub uipi:     bool,   // leaf 7, sub 0 EDX:13 — User Interrupts
    pub invariant_tsc: bool, // leaf 80000007h EDX:8
    pub rdseed:   bool,   // leaf 7, sub 0 EBX:18
    pub rdrand:   bool,   // leaf 1 ECX:30
}

impl Features {
    /// Probe CPUID and build the Stage-2 feature snapshot.
    ///
    /// # Safety
    /// CPUID is always legal; marked `unsafe` for the inline-asm
    /// boundary only.
    pub unsafe fn probe() -> Self {
        let mut f = Features::default();

        // Leaf 1: ECX:30 = RDRAND.
        // SAFETY: CPUID at CPL=0 is always defined.
        let (_, _, ecx1, _) = unsafe { cpuid(0x0000_0001, 0) };
        f.rdrand = ecx1 & (1 << 30) != 0;

        // Leaf 7, sub 0 — extended features.
        let (_, ebx7, ecx7, edx7) = unsafe { cpuid(0x0000_0007, 0) };
        f.rdseed = ebx7 & (1 << 18) != 0;
        f.pku    = ecx7 & (1 <<  3) != 0;
        f.pks    = ecx7 & (1 << 31) != 0;
        f.uipi   = edx7 & (1 << 13) != 0;

        // Leaf 80000001h EDX:20 = NX.
        let (_, _, _, edx_ext) = unsafe { cpuid(0x8000_0001, 0) };
        f.nx = edx_ext & (1 << 20) != 0;

        // Leaf 80000007h EDX:8 = Invariant TSC.
        let (_, _, _, edx_adv) = unsafe { cpuid(0x8000_0007, 0) };
        f.invariant_tsc = edx_adv & (1 << 8) != 0;

        f
    }
}
