//! Task-owned character/syscall counters (`task_struct::ioac`).
//!
//! Updates never acquire a lock or mask interrupts. Atomics permit remote
//! `/proc` readers without a data race; each field is sampled independently,
//! just as Linux's task accounting is not a transaction across all counters.

use core::sync::atomic::{AtomicU64, Ordering};

/// Character and syscall counts. Storage transfer counters are maintained
/// separately on the owning thread group.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskIoAccounting {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
}

/// One cache line per task: independent writers do not bounce a global lock
/// or share these frequently updated words with adjacent task metadata.
#[repr(align(64))]
#[derive(Default)]
pub(crate) struct TaskIoCounters {
    rchar: AtomicU64,
    wchar: AtomicU64,
    syscr: AtomicU64,
    syscw: AtomicU64,
}

#[inline]
fn add(counter: &AtomicU64, amount: u64) {
    // Retain NARF's saturating counters. RMW also prevents a lost update if
    // an accounting caller names a task other than itself. No counter orders
    // unrelated memory; the task's existing owner pins the counter storage.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

impl TaskIoCounters {
    #[inline]
    pub(crate) fn read(&self, ret: i64) {
        if ret > 0 {
            add(&self.rchar, ret as u64);
        }
        add(&self.syscr, 1);
    }

    #[inline]
    pub(crate) fn write(&self, ret: i64) {
        if ret > 0 {
            add(&self.wchar, ret as u64);
        }
        add(&self.syscw, 1);
    }

    /// A resumed syscall contributes bytes, not another syscall attempt.
    #[inline]
    pub(crate) fn reissued(&self, read: bool, ret: i64) {
        if ret > 0 {
            add(if read { &self.rchar } else { &self.wchar }, ret as u64);
        }
    }

    pub(crate) fn snapshot(&self) -> TaskIoAccounting {
        TaskIoAccounting {
            rchar: self.rchar.load(Ordering::Relaxed),
            wchar: self.wchar.load(Ordering::Relaxed),
            syscr: self.syscr.load(Ordering::Relaxed),
            syscw: self.syscw.load(Ordering::Relaxed),
        }
    }

    /// Only the sequential kernel-test fixture resets an existing task.
    pub(crate) fn reset_for_test(&self) {
        self.rchar.store(0, Ordering::Relaxed);
        self.wchar.store(0, Ordering::Relaxed);
        self.syscr.store(0, Ordering::Relaxed);
        self.syscw.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn attempts_eof_and_resumed_calls_keep_distinct_counts() {
        let counters = TaskIoCounters::default();
        counters.read(128);
        counters.read(-9);
        counters.read(0);
        counters.write(64);
        counters.write(-11);
        counters.write(0);
        counters.reissued(true, 32);
        counters.reissued(false, 16);
        counters.reissued(true, -11);
        counters.reissued(false, 0);
        assert_eq!(
            counters.snapshot(),
            TaskIoAccounting {
                rchar: 160,
                wchar: 80,
                syscr: 3,
                syscw: 3,
            }
        );
        counters.reset_for_test();
        assert_eq!(counters.snapshot(), TaskIoAccounting::default());
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let counters = TaskIoCounters {
            rchar: AtomicU64::new(u64::MAX - 1),
            wchar: AtomicU64::new(u64::MAX - 1),
            syscr: AtomicU64::new(u64::MAX),
            syscw: AtomicU64::new(u64::MAX),
        };
        counters.read(8);
        counters.write(8);
        counters.reissued(true, 8);
        counters.reissued(false, 8);
        assert_eq!(
            counters.snapshot(),
            TaskIoAccounting {
                rchar: u64::MAX,
                wchar: u64::MAX,
                syscr: u64::MAX,
                syscw: u64::MAX,
            }
        );
    }

    #[test]
    fn concurrent_updates_and_proc_style_reads_do_not_lose_counts() {
        let counters = TaskIoCounters::default();
        let independent_task = TaskIoCounters::default();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..10_000 {
                        counters.read(8);
                        counters.write(4);
                    }
                });
            }
            let mut previous = TaskIoAccounting::default();
            for _ in 0..10_000 {
                let observed = counters.snapshot();
                // Individual counters are coherent; a multi-field snapshot
                // may straddle an update, so do not assert a byte/call ratio.
                assert!(observed.rchar >= previous.rchar);
                assert!(observed.wchar >= previous.wchar);
                assert!(observed.syscr >= previous.syscr);
                assert!(observed.syscw >= previous.syscw);
                previous = observed;
            }
        });
        assert_eq!(
            counters.snapshot(),
            TaskIoAccounting {
                rchar: 320_000,
                wchar: 160_000,
                syscr: 40_000,
                syscw: 40_000,
            }
        );
        assert_eq!(independent_task.snapshot(), TaskIoAccounting::default());
    }
}
