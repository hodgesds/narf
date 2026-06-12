//! `ro_after_init` — RW during boot, RO once init completes.
//!
//! A handful of data structures (IDT, GDT, vector tables, security
//! policy tables, capability-grant tables installed at boot) are
//! written once during early init and then never again. Mapping them
//! RO after `mark_init_complete()` fires shrinks the attack surface
//! against a write-where bug — an exploit that gets one stray store
//! can't repurpose the IDT into a controlled jump table.
//!
//! Linux landed `__ro_after_init` via Kees Cook's KSPP series in
//! 2016; it relies on the linker placing tagged symbols in a
//! distinct section and the boot path flipping the section's PTEs to
//! RO at the end of init. NARF takes the same shape but adds a
//! [`RoCell<T>`] type that wraps the marker — using one without the
//! `#[ro_after_init]` attribute would still work, but the type tells
//! the reader "this is going RO."
//!
//! The runtime cost is zero post-init: subsequent reads go through
//! the same PTE shape the rest of the kernel uses.
//!
//! References:
//!   * Kees Cook's KSPP commit: `__ro_after_init` in
//!     `include/linux/cache.h`.
//!   * grsecurity's `kernexec` for the section-write-protect history.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// Global "init complete" latch. Set exactly once via
/// [`mark_init_complete`]. Read by [`RoCell::set`] to enforce the
/// "RW only during boot" invariant.
static INIT_COMPLETE: AtomicBool = AtomicBool::new(false);

/// Memory section name. The linker places anything marked
/// `#[link_section = ".ro_after_init"]` (or
/// `#[link_section = RO_AFTER_INIT_SECTION]`) here. The boot path
/// flips this range to RO after [`mark_init_complete`] fires.
pub const RO_AFTER_INIT_SECTION: &str = ".ro_after_init";

/// Convenience attribute literal: `#[link_section = SECTION_ATTR]`
/// equivalent — see usage in callers. Kept as a `&str` constant so
/// helper macros can interpolate it.
pub const SECTION_ATTR: &str = ".ro_after_init";

/// Wrapper around an interior-mutable cell that gates writes on
/// `!INIT_COMPLETE`. After [`mark_init_complete`], `set` panics
/// rather than silently corrupting; the boot path is expected to
/// install all values it cares about before marking init done.
#[derive(Debug)]
pub struct RoCell<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: `RoCell` only mutates during single-threaded boot (when
// `INIT_COMPLETE` is false); after that, reads are immutable. The
// post-init "make page RO" step removes write capability entirely.
unsafe impl<T: Sync> Sync for RoCell<T> {}

impl<T> RoCell<T> {
    /// Construct with the boot-time initial value. `const fn` so
    /// `static` items can use it.
    pub const fn new(initial: T) -> Self {
        Self {
            inner: UnsafeCell::new(initial),
        }
    }

    /// Read the contained value. Always safe — the read-only-after-init
    /// invariant means after the first phase the underlying storage
    /// never changes.
    pub fn get(&self) -> &T {
        // SAFETY: post-init, the underlying memory never mutates;
        // pre-init, only boot-time mutators (`set`) touch it, and
        // they take `&self` exclusively in the single-threaded boot
        // path. The borrow returned here is short-lived (typically
        // immediate dereference) so even if a parallel `set` were
        // somehow racing it would read either the old or new value
        // atomically by virtue of `T: Copy` requirements upstream.
        // SAFETY: Valid memory or trusted environment
        unsafe { &*self.inner.get() }
    }

    /// Replace the value. Panics if [`mark_init_complete`] has
    /// already fired.
    ///
    /// # Safety
    /// During boot the kernel is effectively single-threaded; calling
    /// `set` from a parallel boot-time task is the caller's problem.
    /// Post-init this panics rather than corrupting.
    pub unsafe fn set(&self, value: T) {
        if INIT_COMPLETE.load(Ordering::Acquire) {
            panic!("RoCell::set after mark_init_complete");
        }
        // SAFETY: as documented on the function.
        unsafe {
            *self.inner.get() = value;
        }
    }
}

/// `true` iff [`mark_init_complete`] has fired.
#[inline]
pub fn is_init_complete() -> bool {
    INIT_COMPLETE.load(Ordering::Acquire)
}

/// Latch the "init complete" flag. Subsequent [`RoCell::set`] calls
/// panic. The boot path follows this immediately by flipping the
/// `.ro_after_init` section's PTEs to RO at the page-table layer
/// (separate concern — this function only flips the latch).
///
/// Idempotent: calling more than once is a no-op.
#[inline]
pub fn mark_init_complete() {
    INIT_COMPLETE.store(true, Ordering::Release);
}

/// Test-only: reset the latch. Used by smokes that need to exercise
/// the RW phase repeatedly. **DO NOT call from production code.**
#[doc(hidden)]
pub fn _reset_for_test() {
    INIT_COMPLETE.store(false, Ordering::Release);
}
