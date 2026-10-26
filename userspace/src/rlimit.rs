//! Process-owned Linux resource limits.
//!
//! Linux's `task_rlimit` uses READ_ONCE for individual words; get/setrlimit
//! serialize complete pairs with the group leader's task lock. Rust atomics
//! supply the word reads without introducing a data race through volatile or
//! ordinary shared memory. The lock below is shared only by this process.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

pub(crate) const COUNT: usize = 16;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Limit {
    pub cur: u64,
    pub max: u64,
}

#[derive(Debug)]
struct AtomicLimit {
    cur: AtomicU64,
    max: AtomicU64,
}

#[derive(Debug)]
pub(crate) struct ProcessLimits {
    transaction: IrqSafeSpinLock<()>,
    values: [AtomicLimit; COUNT],
}

impl ProcessLimits {
    pub(crate) fn new(values: [Limit; COUNT]) -> Self {
        Self {
            transaction: IrqSafeSpinLock::new(()),
            values: core::array::from_fn(|i| AtomicLimit {
                cur: AtomicU64::new(values[i].cur),
                max: AtomicU64::new(values[i].max),
            }),
        }
    }

    /// Individual words only: a concurrent update may fall between the two
    /// loads. This has Linux's READ_ONCE semantics, not pair-snapshot semantics.
    #[inline]
    pub(crate) fn read_once(&self, resource: usize) -> Option<Limit> {
        let value = self.values.get(resource)?;
        Some(Limit {
            cur: value.cur.load(Ordering::Relaxed),
            max: value.max.load(Ordering::Relaxed),
        })
    }

    pub(crate) fn transaction<R>(&self, f: impl FnOnce(&LockedLimits<'_>) -> R) -> R {
        let _guard = self.transaction.lock();
        f(&LockedLimits(self))
    }

    pub(crate) fn snapshot(&self) -> [Limit; COUNT] {
        self.transaction(|locked| locked.snapshot())
    }
}

/// Only constructed while this process's transaction lock is held.
#[derive(Debug)]
pub(crate) struct LockedLimits<'a>(&'a ProcessLimits);

impl LockedLimits<'_> {
    pub(crate) fn read(&self, resource: usize) -> Option<Limit> {
        self.0.read_once(resource)
    }

    pub(crate) fn write(&self, resource: usize, value: Limit) {
        let destination = &self.0.values[resource];
        destination.cur.store(value.cur, Ordering::Relaxed);
        destination.max.store(value.max, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> [Limit; COUNT] {
        core::array::from_fn(|i| self.read(i).expect("resource in fixed limit array"))
    }

    pub(crate) fn replace(&self, values: [Limit; COUNT]) {
        for (i, value) in values.into_iter().enumerate() {
            self.write(i, value);
        }
    }
}
