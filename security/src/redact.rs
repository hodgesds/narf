//! Pointer redaction — strip kernel addresses from any diagnostic
//! that doesn't carry a `Cap<KernelDebug>`.
//!
//! Linux has `%pK` for printk format strings, but it's a runtime
//! policy knob (kptr_restrict) — distros pick one of three settings
//! and stuck with it system-wide. NARF makes redaction a *capability*
//! check: the reader proves they hold the debug cap, or all kernel
//! VAs come out as `*`.
//!
//! The cutoff is the kernel-half base: x86_64 uses
//! `0xFFFF_8000_0000_0000` and aarch64 uses `0xFFFF_0000_0000_0000`
//! by convention. Anything at or above the cutoff is "kernel space"
//! and gets redacted; user-half pointers pass through (they don't
//! leak kernel layout).

use core::fmt;

/// Kernel-VA cutoff. Addresses at or above this value are kernel
/// virtual addresses; below it is user space.
///
/// x86_64 splits VAs canonically at bit 47 (sign-extended); aarch64
/// uses bit 55. The cutoffs differ but the redaction rule is the
/// same: anything in the kernel half leaks layout.
#[inline]
pub const fn kernel_va_cutoff() -> u64 {
    if cfg!(target_arch = "x86_64") {
        0xFFFF_8000_0000_0000
    } else if cfg!(target_arch = "aarch64") {
        0xFFFF_0000_0000_0000
    } else {
        // Conservative default for unknown architectures.
        u64::MAX / 2
    }
}

/// Redact a 64-bit address. Returns `"*"` (as a `Redact` formatter)
/// if the address is in the kernel half; otherwise prints the address
/// as hex.
///
/// Use in `{:?}` / `{}` contexts:
/// ```ignore
/// log!("ptr = {}", redact_pointer(addr));
/// ```
#[inline]
pub fn redact_pointer(addr: u64) -> Redact {
    Redact { addr }
}

/// `Display`/`Debug` wrapper around a redacted pointer.
#[derive(Copy, Clone)]
pub struct Redact {
    addr: u64,
}

impl Redact {
    /// `true` iff this address is in the kernel half (i.e. would be
    /// redacted in the default policy).
    #[inline]
    pub fn is_kernel(&self) -> bool {
        self.addr >= kernel_va_cutoff()
    }

    /// Reveal the underlying address. Should only be called by code
    /// that has already proven the reader holds `Cap<KernelDebug>`.
    /// This is just an accessor; the cap-check is the caller's
    /// responsibility — wrap it in a function whose signature
    /// requires the cap.
    #[inline]
    pub fn reveal(&self) -> u64 {
        self.addr
    }
}

impl fmt::Display for Redact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_kernel() {
            f.write_str("*")
        } else {
            write!(f, "{:#x}", self.addr)
        }
    }
}

impl fmt::Debug for Redact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same shape as Display so {:?} doesn't accidentally bypass
        // redaction.
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl fmt::LowerHex for Redact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_kernel() {
            f.write_str("*")
        } else {
            write!(f, "{:x}", self.addr)
        }
    }
}
