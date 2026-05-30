//! Per-module reference count.
//!
//! Linux ref: `linux/kernel/module/main.c::try_module_get`
//! (`main.c:907`) and `module_put` (`main.c:923`).
//!
//! Bumped on every:
//!   * Symbol export held by another module.
//!   * Character device the module registered that has an open fd.
//!
//! Decremented on the reverse. `rmmod` refuses to unload while
//! refcount > 0.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Refcount for one module. Cheap atomic, no allocation.
#[derive(Debug, Default)]
pub struct RefCount(pub AtomicUsize);

impl RefCount {
    pub const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// Add one reference. Returns the new count.
    pub fn get(&self) -> usize {
        self.0.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Drop one reference. Returns the new count.
    /// Panics if the count was already zero — that's a use-after-free.
    pub fn put(&self) -> usize {
        let prev = self.0.fetch_sub(1, Ordering::AcqRel);
        assert!(prev > 0, "RefCount::put underflow");
        prev - 1
    }

    /// Snapshot current count without modifying it.
    pub fn snapshot(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    /// True iff no references are held.
    pub fn is_zero(&self) -> bool {
        self.snapshot() == 0
    }
}
