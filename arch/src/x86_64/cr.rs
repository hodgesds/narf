//! Control-register access.
//!
//! Every entry point takes the compiler_fence(SeqCst) pair per
//! `arch/` §4: CR4 in particular gates PKS / UIPI / OSFXSR, and fat
//! LTO reordering across the write is specifically a correctness
//! hazard the spec names.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// CR4 bit: PKS (bit 24). Enables supervisor protection keys
/// (IA32_PKRS-based domain rights).
pub const CR4_PKS: u64 = 1 << 24;
/// CR4 bit: PKE (bit 22). Enables user-mode protection keys.
pub const CR4_PKE: u64 = 1 << 22;

/// Read CR4.
///
/// # Safety
/// `MOV from CR4` is legal at CPL=0.
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let v: u64;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MOV from CR4 at CPL=0 is always legal.
    unsafe {
        asm!("mov {out}, cr4", out = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write CR4.
///
/// # Safety
/// - Only bits documented as writable may be set.
/// - Enabling new features may require other setup first (e.g. CR4.PKS
///   requires CPUID.(07h:0).ECX:31=1, else `#GP`).
#[inline]
pub unsafe fn write_cr4(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller verified feature availability.
    unsafe {
        asm!("mov cr4, {v}", v = in(reg) value,
             options(nomem, nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}
