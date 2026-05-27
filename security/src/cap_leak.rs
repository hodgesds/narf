//! Capability-leak detection.
//!
//! NARF's privilege model: every privileged operation goes through a
//! `Cap<T, Right>`. The cap is a token whose presence in scope is
//! the right; types like `Cap<Crypto, Write>` mean "this scope can
//! write to crypto state."
//!
//! A *cap leak* is a `Cap<_, Write>` held across an `.await` point
//! where a different `DomainId` might observe it — i.e. the suspended
//! task carries the cap, the executor schedules a task from another
//! domain on this core, and now the second task can speculatively
//! read the cap's address from the cache. That's a layout-leak
//! attack vector (Spectre v1 against the dispatcher).
//!
//! The mechanism here is debug-only: a runtime assert that's a
//! no-op in release builds. The compile-time defence is the
//! `#[no_cap_leak]` attribute the lint surface will add (deferred
//! work; this module is the receiver).
//!
//! References:
//!   * NARF design doc `DESIGN.md` §3 — capability model.
//!   * Linux `kernel/locking/lockdep.c` for the spiritual analogue:
//!     debug-only state machine that detects bad ownership flow.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Reason a cap-leak check failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapLeakError {
    /// Cap of `Write` strength was held while crossing a domain
    /// boundary.
    WriteCapCrossedDomain { from: u8, to: u8, cap_tag: u32 },
    /// Cap of any strength was held across an `.await` AND the task
    /// resumed in a different domain (the kernel scheduler does NOT
    /// guarantee task-to-domain affinity).
    AwaitCrossedDomain { tag: u32 },
}

/// Per-task counter of currently held write-capable caps. Set to a
/// nonzero value by `cap_acquire_write` (a debug-only hook from the
/// cap module); decremented by `cap_release_write`. The cap-leak
/// assert checks this value alongside the domain transition.
///
/// In release builds the asserts compile out and these atomics are
/// untouched.
static WRITE_CAPS_HELD: AtomicU32 = AtomicU32::new(0);

/// Current DomainId snapshot. Updated by the domain backend's
/// `enter_domain` / `exit_domain` shims.
static CURRENT_DOMAIN: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the *previous* DomainId — what we were running in
/// before the last switch. The cap-leak assert compares this with
/// the current value to detect crossings.
static PREVIOUS_DOMAIN: AtomicU64 = AtomicU64::new(0);

/// Assert no write-capable cap leaked across the last domain transition.
///
/// In debug builds: walks the per-task held-caps counter; if any
/// `Write` cap is held while `CURRENT_DOMAIN != PREVIOUS_DOMAIN`,
/// returns [`CapLeakError::WriteCapCrossedDomain`].
///
/// In release builds: returns `Ok(())` unconditionally — the cap-leak
/// machinery is purely a debug aid; the type-system invariant
/// (`#[no_cap_leak]` on async fns) is what enforces in release.
#[inline]
pub fn assert_no_cap_leak() -> Result<(), CapLeakError> {
    let cur = CURRENT_DOMAIN.load(Ordering::Acquire);
    let prev = PREVIOUS_DOMAIN.load(Ordering::Acquire);
    let held = WRITE_CAPS_HELD.load(Ordering::Acquire);
    if cur != prev && held > 0 {
        return Err(CapLeakError::WriteCapCrossedDomain {
            from: prev as u8,
            to: cur as u8,
            cap_tag: held,
        });
    }
    Ok(())
}

/// Debug-only hook: a write cap was just acquired. Tag is a
/// caller-chosen identifier (e.g. the cap type's hash) so leaks can
/// be attributed.
#[inline]
pub fn debug_acquire_write(_tag: u32) {
    WRITE_CAPS_HELD.fetch_add(1, Ordering::AcqRel);
}

/// Debug-only hook: a write cap was just released.
#[inline]
pub fn debug_release_write(_tag: u32) {
    WRITE_CAPS_HELD.fetch_sub(1, Ordering::AcqRel);
}

/// Debug-only hook: domain transition just occurred.
#[inline]
pub fn debug_domain_transition(new_domain: u64) {
    let cur = CURRENT_DOMAIN.swap(new_domain, Ordering::AcqRel);
    PREVIOUS_DOMAIN.store(cur, Ordering::Release);
}

/// Test-only: reset the counters. Used by smokes that need to start
/// from a known state.
#[doc(hidden)]
pub fn _reset_for_test() {
    WRITE_CAPS_HELD.store(0, Ordering::Release);
    CURRENT_DOMAIN.store(0, Ordering::Release);
    PREVIOUS_DOMAIN.store(0, Ordering::Release);
}
