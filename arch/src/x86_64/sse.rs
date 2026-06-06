//! SSE / FXSR enable. Required for SSE2 instruction execution and for
//! `FXSAVE` / `FXRSTOR` context save (which the trap path will need
//! once SSE registers are in scope across preemption).
//!
//! x86_64 mandates SSE2 as part of the architectural baseline — there
//! is no `supported()` predicate; long-mode CPUs ALWAYS have SSE2.
//! What's not on by default is the OS opt-in:
//!
//!   CR4.OSFXSR    (bit 9)  — Operating-system FXSAVE/FXRSTOR support.
//!                            With this clear, `FXSAVE`/`FXRSTOR` are
//!                            `#UD`. With it set, `MOVUPS`,
//!                            `MOVQ %xmm`, etc. are legal.
//!   CR4.OSXMMEXCPT (bit 10) — Route SIMD floating-point exceptions
//!                             through `#XF` (vector 19) instead of
//!                             `#UD`.
//!
//! Without these, the first user-mode SSE instruction raises `#UD`
//! and the task dies with SIGILL — which is exactly what musl-static
//! binaries hit during their init's TLS memcpy (musl's TLS path uses
//! `movq %rbx, %xmm0` + `punpcklqdq` to bulk-zero / bulk-copy a
//! cache line).

use crate::x86_64::cr::{read_cr4, write_cr4};

/// CR4 bit 9. Architectural — Intel SDM Vol 3 §2.5.
pub const CR4_OSFXSR: u64 = 1 << 9;

/// CR4 bit 10. Architectural — Intel SDM Vol 3 §2.5.
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;

/// Set CR4.OSFXSR and CR4.OSXMMEXCPT. Both are idempotent — no-op if
/// already set. Must be called once per CPU after paging is up and
/// before any user-mode entry that could execute SSE.
///
/// # Safety
/// CPL = 0. SSE2 is architectural on x86_64 so this never traps.
#[inline]
pub unsafe fn enable() {
    const MASK: u64 = CR4_OSFXSR | CR4_OSXMMEXCPT;
    // SAFETY: caller-asserted CPL=0.
    let v = unsafe { read_cr4() };
    if v & MASK != MASK {
        // SAFETY: bits 9 and 10 are documented architectural; the
        // read-modify-write preserves every other CR4 bit.
        unsafe {
            write_cr4(v | MASK);
        }
    }
}

/// Read-back: `true` iff both CR4.OSFXSR and CR4.OSXMMEXCPT are set.
#[inline]
pub fn is_enabled() -> bool {
    const MASK: u64 = CR4_OSFXSR | CR4_OSXMMEXCPT;
    // SAFETY: MOV from CR4 at CPL=0 is always defined.
    let v = unsafe { read_cr4() };
    v & MASK == MASK
}
