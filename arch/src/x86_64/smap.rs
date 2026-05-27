//! SMAP — Supervisor Mode Access Prevention.
//!
//! CR4 bit 21. When set, any data access (load or store) from a
//! supervisor-mode (CPL=0) instruction to a user-accessible page
//! (PTE.U=1) faults — *unless* the EFLAGS.AC bit is set. The
//! `STAC`/`CLAC` instructions set/clear AC atomically; everything in
//! between is an explicit "I am the kernel deliberately reaching
//! into user memory" annotation. Out of that window, the kernel
//! literally cannot touch user pages, full stop.
//!
//! NARF stance:
//!
//!   * Linux exposes `copy_from_user` / `copy_to_user` which open
//!     a per-call STAC/CLAC window and rely on developers calling
//!     the right helper. Forgetting it is a silent vulnerability
//!     class — a kernel that touches user memory directly will
//!     *succeed* on a non-SMAP CPU and *fault* on SMAP, so the bug
//!     stays latent on bring-up.
//!   * NARF wraps every user-memory touch in [`with_user_access`],
//!     which takes a closure. The compiler enforces lexical scope.
//!     Forgetting it is a *type* error (the user pointer surface
//!     is `unsafe` + needs the cap to even get the pointer), not
//!     a runtime check.
//!   * On Renoir + Phoenix the bit is always available; the
//!     `supported()` check is for QEMU TCG without `-cpu max`
//!     and for the same reason `cargo xtask test` includes a
//!     `Skip` path.
//!
//! References:
//!   * Intel SDM Vol 3 §4.6.1 — "User and Supervisor Mode Access".
//!   * AMD APM Vol 2 §5.5 — same.
//!   * Linux `arch/x86/include/asm/uaccess.h` (`user_access_begin` /
//!     `user_access_end`).
//!   * grsecurity UDEREF for the historical motivation (Brad
//!     Spengler's 2011 patch series; SMAP is the HW realisation).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::arch::asm;

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::cr::{read_cr4, write_cr4};

/// CR4 bit 21. Architectural — Intel SDM Vol 3 §2.5.
pub const CR4_SMAP: u64 = 1 << 21;

/// `true` iff CPUID(7, 0).EBX[20] is set.
///
/// Renoir (Zen2) and Phoenix (Zen4) both set this bit. Older AMD
/// parts (Bulldozer, Piledriver, Steamroller) lack SMAP; the
/// `with_user_access` helper degrades to a plain closure call there
/// (still type-safe, just no HW enforcement).
#[inline]
pub fn supported() -> bool {
    // SAFETY: CPUID always legal at CPL=0.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub 0 valid because max >= 7.
    let (_, ebx, _, _) = unsafe { cpuid(7, 0) };
    ebx & (1 << 20) != 0
}

/// Set CR4.SMAP. No-op if already set.
///
/// # Safety
/// CPL = 0; `supported()` returned true.
#[inline]
pub unsafe fn enable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    if v & CR4_SMAP == 0 {
        // SAFETY: bit 21 reserved/preserved for non-SMAP CPUs is
        // unchanged by `read | CR4_SMAP` on a CPU that has the bit
        // (the caller proved `supported()`).
        unsafe {
            write_cr4(v | CR4_SMAP);
        }
    }
}

/// Read-back: `true` iff CR4.SMAP is currently set on this CPU.
#[inline]
pub fn is_enabled() -> bool {
    // SAFETY: MOV from CR4 at CPL=0 always defined.
    let v = unsafe { read_cr4() };
    v & CR4_SMAP != 0
}

/// Set EFLAGS.AC (open the user-access window).
///
/// On a CPU without SMAP the instruction is a NOP (the bit exists
/// but enforces nothing). `STAC` is a single byte (`0F 01 CB`) and
/// is always safe to encode — it's been valid since Haswell.
///
/// # Safety
/// Should only be called via [`with_user_access`]; raw use risks
/// leaving the window open across a context switch (the kernel
/// would silently regain user-memory access for the next syscall).
#[inline(always)]
pub unsafe fn stac() {
    // SAFETY: encoding documented above; clobbers no registers.
    unsafe {
        asm!("stac", options(nomem, nostack, preserves_flags));
    }
}

/// Clear EFLAGS.AC (close the user-access window).
///
/// # Safety
/// Should only be called via [`with_user_access`].
#[inline(always)]
pub unsafe fn clac() {
    // SAFETY: encoding documented above; clobbers no registers.
    unsafe {
        asm!("clac", options(nomem, nostack, preserves_flags));
    }
}

/// Bracket `f` with `STAC`/`CLAC` — the only sanctioned way to touch
/// user memory from kernel code.
///
/// This is the centrepiece of the "more secure than Linux" claim for
/// the kernel-to-user channel: missing brackets aren't a runtime bug,
/// they're a type-system error (every user-memory accessor in NARF's
/// surface takes a `&UserPtr<T>` whose deref is `unsafe` and is only
/// permitted inside this closure).
///
/// On CPUs without SMAP the STAC/CLAC are NOPs (no AC bit to toggle)
/// and the closure executes verbatim — the kernel still upholds the
/// type-level invariant, just without HW enforcement.
///
/// # Safety
/// `f` must not switch context, sleep across an await, or call into
/// any path that itself opens a nested user-access window. The closure
/// body is short-lived and only accesses user pointers it has
/// pre-validated (range + alignment + capability).
#[inline]
pub unsafe fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: STAC is a NOP on non-SMAP CPUs and a single-instruction
    // EFLAGS.AC toggle on SMAP CPUs. Either way it doesn't touch
    // memory or other regs.
    unsafe {
        stac();
    }
    let r = f();
    // SAFETY: same.
    unsafe {
        clac();
    }
    r
}

/// Clear CR4.SMAP. Reserved for unit-test reset paths only.
///
/// **DO NOT call this from production code.**
///
/// # Safety
/// CPL = 0.
#[inline]
pub unsafe fn disable_for_test() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    // SAFETY: clearing bit 21 is architecturally legal.
    unsafe {
        write_cr4(v & !CR4_SMAP);
    }
}

/// Read EFLAGS.AC. Useful for tests that want to verify the
/// STAC/CLAC bracket actually flipped the bit on SMAP-capable HW.
#[inline]
pub fn read_ac() -> bool {
    let f: u64;
    // SAFETY: PUSHFQ + POP is always legal at CPL=0.
    unsafe {
        asm!(
            "pushfq",
            "pop {f}",
            f = out(reg) f,
            options(nostack, preserves_flags),
        );
    }
    f & (1 << 18) != 0
}
