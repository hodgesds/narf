//! XSAVE state-component management.
//!
//! Spec: `arch/specification/modern-cpu.md` §2.
//!
//! Detects which extended state components the CPU advertises
//! (AVX, AVX-512, AMX, PKRU, ...) and exposes XCR0 / IA32_XSS
//! enable + XSAVE / XRSTOR instruction wrappers.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_XSS: u32 = 0x0DA0;

// XCR0 / XSS component bits.
pub const XSAVE_X87:           u64 = 1 << 0;
pub const XSAVE_SSE:           u64 = 1 << 1;
pub const XSAVE_AVX:           u64 = 1 << 2;
pub const XSAVE_BNDREG:        u64 = 1 << 3;  // MPX bound registers (legacy)
pub const XSAVE_BNDCSR:        u64 = 1 << 4;  // MPX cfg + status (legacy)
pub const XSAVE_AVX512_OPMASK: u64 = 1 << 5;
pub const XSAVE_AVX512_ZMM_HI: u64 = 1 << 6;
pub const XSAVE_AVX512_HI16:   u64 = 1 << 7;
pub const XSAVE_PT:            u64 = 1 << 8;  // Intel PT (XSS-only)
pub const XSAVE_PKRU:          u64 = 1 << 9;
pub const XSAVE_AMX_TILECFG:   u64 = 1 << 17;
pub const XSAVE_AMX_TILEDATA:  u64 = 1 << 18;

// AVX-512 group: opmask + ZMM_Hi + Hi16_ZMM are the three
// components the OS must enable together for AVX-512 to work.
pub const XSAVE_AVX512_GROUP: u64 =
    XSAVE_AVX512_OPMASK | XSAVE_AVX512_ZMM_HI | XSAVE_AVX512_HI16;

// AMX group: tilecfg + tiledata.
pub const XSAVE_AMX_GROUP: u64 = XSAVE_AMX_TILECFG | XSAVE_AMX_TILEDATA;

#[derive(Copy, Clone, Debug, Default)]
pub struct XsaveCaps {
    pub xcr0_supported:        u64,
    pub xss_supported:         u64,
    pub area_size_xcr0:        u32,
    pub area_size_xcr0_xss:    u32,
    pub xsaveopt:              bool,
    pub xsavec:                bool,
    pub xsaves:                bool,
    pub xgetbv1:               bool,
    pub avx:                   bool,
    pub avx512:                bool,
    pub amx:                   bool,
    pub pkru:                  bool,
}

pub fn caps() -> XsaveCaps {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x0D { return XsaveCaps::default(); }
    // SAFETY: leaf 0x0D valid.
    let (eax_0, ebx_0, ecx_0, edx_0) = unsafe { cpuid(0x0D, 0) };
    let xcr0_supp = ((edx_0 as u64) << 32) | eax_0 as u64;
    let area_xcr0 = ecx_0;
    // SAFETY: sub-leaf 1 valid when 0 returned non-zero.
    let (eax_1, ebx_1, ecx_1, edx_1) = unsafe { cpuid(0x0D, 1) };
    let xss_supp  = ((edx_1 as u64) << 32) | ecx_1 as u64;
    let area_xss  = ebx_1;
    let xsaveopt  = eax_1 & (1 << 0) != 0;
    let xsavec    = eax_1 & (1 << 1) != 0;
    let xgetbv1   = eax_1 & (1 << 2) != 0;
    let xsaves    = eax_1 & (1 << 3) != 0;
    let _ = ebx_0;
    XsaveCaps {
        xcr0_supported:     xcr0_supp,
        xss_supported:      xss_supp,
        area_size_xcr0:     area_xcr0,
        area_size_xcr0_xss: area_xss,
        xsaveopt, xsavec, xsaves, xgetbv1,
        avx:    xcr0_supp & XSAVE_AVX != 0,
        avx512: (xcr0_supp & XSAVE_AVX512_GROUP) == XSAVE_AVX512_GROUP,
        amx:    (xcr0_supp & XSAVE_AMX_GROUP) == XSAVE_AMX_GROUP,
        pkru:   xcr0_supp & XSAVE_PKRU != 0,
    }
}

/// Read XCR0 via `XGETBV ECX = 0`.
///
/// # Safety
/// CR4.OSXSAVE must be set (NARF boot validation enforces this).
pub unsafe fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Write XCR0 via `XSETBV ECX = 0`.
///
/// # Safety
/// CR4.OSXSAVE = 1; `v` only contains bits set in
/// `caps().xcr0_supported`.
pub unsafe fn write_xcr0(v: u64) {
    let lo = v as u32;
    let hi = (v >> 32) as u32;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read `IA32_XSS`.
///
/// # Safety
/// CPL = 0; XSAVES supported (`caps().xsaves == true`).
pub unsafe fn read_xss() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_XSS) }
}

/// Write `IA32_XSS`.
///
/// # Safety
/// CPL = 0; bits in `v` must be ⊆ `caps().xss_supported`.
pub unsafe fn write_xss(v: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_XSS, v); }
}

/// Default boot policy: enable every "safe" user component the
/// CPU advertises. AMX is included because the spec asserts the
/// kernel's enable-once-then-inherit model — userspace doesn't
/// need a separate ARCH_REQ_XCOMP_PERM dance.
///
/// # Safety
/// CR4.OSXSAVE = 1.
pub unsafe fn enable_default() {
    let c = caps();
    let mut v = XSAVE_X87 | XSAVE_SSE;
    if c.avx       { v |= XSAVE_AVX; }
    if c.avx512    { v |= XSAVE_AVX512_GROUP; }
    if c.pkru      { v |= XSAVE_PKRU; }
    if c.amx       { v |= XSAVE_AMX_GROUP; }
    // Mask against actually-supported bits to be safe.
    v &= c.xcr0_supported;
    // SAFETY: caller-asserted; v is supported subset.
    unsafe { write_xcr0(v); }
}

/// Save the components selected by `mask` into `buf`.
///
/// # Safety
/// `buf` is at least `caps().area_size_xcr0_xss` bytes, 64-byte
/// aligned (XSAVE alignment requirement). `mask` ⊆ XCR0 ∪ XSS.
pub unsafe fn xsave(buf: *mut u8, mask: u64) {
    let lo = mask as u32;
    let hi = (mask >> 32) as u32;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "xsave [{p}]",
            p = in(reg) buf,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// Restore the components selected by `mask` from `buf`.
///
/// # Safety
/// `buf` was produced by a matching `xsave` (same components,
/// same kind: standard/compacted).
pub unsafe fn xrstor(buf: *const u8, mask: u64) {
    let lo = mask as u32;
    let hi = (mask >> 32) as u32;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "xrstor [{p}]",
            p = in(reg) buf,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}
