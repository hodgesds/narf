//! Intel LASS — Linear Address Space Separation.
//!
//! Spec: `arch/specification/cpu-arch-extensions.md` §5.
//!
//! When CR4.LASS is set, a CPL = 0 access to a user-half VA
//! (sign-bit = 0) faults, and a CPL = 3 access to a kernel-half
//! VA (sign-bit = 1) faults — independently of paging
//! permissions. Defeats SMAP-bypass-style probes that rely on
//! the kernel touching user memory while CR4.SMAP is clear.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::cr::{read_cr4, write_cr4};

pub const CR4_LASS: u64 = 1 << 27;

/// `true` iff CPUID(7, 1).EAX[6] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub-leaf 1 valid.
    let (eax, _, _, _) = unsafe { cpuid(7, 1) };
    eax & (1 << 6) != 0
}

/// Set CR4.LASS.
///
/// # Safety
/// CPL = 0; LASS supported.
pub unsafe fn enable_cr4() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    unsafe {
        write_cr4(v | CR4_LASS);
    }
}

/// Clear CR4.LASS.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_cr4() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    unsafe {
        write_cr4(v & !CR4_LASS);
    }
}
