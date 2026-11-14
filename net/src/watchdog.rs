//! Net-device transmit watchdog — Linux `dev_watchdog`
//! (`net/sched/sch_generic.c`) and `ndo_tx_timeout`.
//!
//! Every NIC with a transmit timeout registers one [`DevWatchdog`]: a wheel
//! `timer_list` firing every `watchdog_timeo`. Its callback asks the driver
//! whether a transmit has been stuck past the timeout with carrier up
//! ([`NetdevWatchdog::tx_timed_out`], the `netif_tx_queue_stopped` +
//! `trans_start` check, which the driver keeps per descriptor). When one
//! has, it queues the driver's recovery ([`NetdevWatchdog::tx_timeout`],
//! `ndo_tx_timeout` → the driver's reset task) on `system_wq`: recovery
//! resets hardware and may wait, which a timer callback must not. The
//! timer re-arms each period while the device lives.
//!
//! Lifetime: the device is held weakly, so a removed device stops its
//! watchdog at the next period. The watchdog state is reference counted
//! (`Arc`): a pending timer and a queued recovery work each hold one
//! reference, taken when they become pending and given back by their
//! callback, so either may run after the last [`DevWatchdog`] handle is
//! gone.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

use narf_scheduler::narf_time::timer::{self, TimerList, TimerRef};
use narf_scheduler::workqueue::{self, WorkFn, WorkRef, WorkStruct};

/// A NIC's side of the transmit watchdog.
pub trait NetdevWatchdog: Send + Sync + 'static {
    /// Whether a transmit has waited past the timeout with carrier up, at
    /// counter time `now_cycles`, and recovery is neither in progress nor
    /// meaningless (device detached or suspended). Called from the timer
    /// (executor context, no locks held); must not wait.
    fn tx_timed_out(&self, now_cycles: u64) -> bool;

    /// `ndo_tx_timeout` and its reset task: count the timeout and recover
    /// the transmit path. Called from a work item (task context).
    fn tx_timeout(&self);
}

/// The watchdog state. `timer` and `work` are reached from their callbacks
/// by offset, so the struct is `repr(C)` and lives in an `Arc` allocation.
#[repr(C)]
struct Inner {
    timer: TimerList,
    work: WorkStruct,
    dev: Weak<dyn NetdevWatchdog>,
    timeo_jiffies: u64,
    /// Recoveries queued (diagnostic, tests).
    fired: AtomicU64,
}

/// A running transmit watchdog. Dropping it stops the timer; a recovery
/// already queued still runs.
pub struct DevWatchdog(Arc<Inner>);

impl core::fmt::Debug for DevWatchdog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevWatchdog")
            .field("timeo_jiffies", &self.0.timeo_jiffies)
            .field("fired", &self.0.fired.load(Ordering::Relaxed))
            .finish()
    }
}

/// Arm the timer for one period, taking the pending reference if it was
/// idle.
fn arm(inner: &Arc<Inner>) {
    let j = timer::jiffies() + inner.timeo_jiffies;
    // SAFETY: the timer lives in the `Arc` allocation, kept alive by the
    // reference a pending timer holds.
    if unsafe { timer::mod_timer_checked(&inner.timer, j, false) } == 0 {
        // SAFETY: the caller holds a strong reference; the callback gives
        // this one back.
        unsafe { Arc::increment_strong_count(Arc::as_ptr(inner)) };
    }
}

fn from_timer(r: TimerRef) -> *const Inner {
    // `timer` is the first field.
    r.as_ptr() as *const Inner
}

fn from_work(r: WorkRef) -> *const Inner {
    // SAFETY: `work` is a field of the repr(C) `Inner`; step back to it.
    unsafe { (r.as_ptr() as *const u8).sub(core::mem::offset_of!(Inner, work)) as *const Inner }
}

/// `dev_watchdog`.
fn watchdog_timer_fn(r: TimerRef) {
    // SAFETY: only watchdogs use this callback; the pending timer held this
    // strong reference.
    let inner = unsafe { Arc::from_raw(from_timer(r)) };
    let Some(dev) = inner.dev.upgrade() else {
        // The device is gone: the watchdog stops with it.
        return;
    };
    if dev.tx_timed_out(narf_scheduler::narf_time::now_cycles()) {
        // SAFETY: the work lives in the `Arc` allocation, kept alive by the
        // reference a queued work holds (taken below).
        if unsafe { workqueue::queue_work(workqueue::system_wq(), &inner.work) } {
            // SAFETY: as in `arm`; the work function gives it back.
            unsafe { Arc::increment_strong_count(Arc::as_ptr(&inner)) };
            inner.fired.fetch_add(1, Ordering::Relaxed);
        }
    }
    drop(dev);
    arm(&inner);
}

/// The reset task: `ndo_tx_timeout`'s recovery in task context.
fn watchdog_work_fn(r: WorkRef) {
    // SAFETY: only watchdogs use this work; the queued work held this
    // strong reference.
    let inner = unsafe { Arc::from_raw(from_work(r)) };
    if let Some(dev) = inner.dev.upgrade() {
        dev.tx_timeout();
    }
}

impl DevWatchdog {
    /// `dev_activate` → `dev_watchdog_up`: watch `dev` every `timeo_ns`
    /// (`dev->watchdog_timeo`; Linux's default is 5 s).
    pub fn start(dev: Weak<dyn NetdevWatchdog>, timeo_ns: u64) -> Self {
        Self(Self::start_inner(dev, timeo_ns))
    }

    /// Start a watchdog that lives exactly as long as `dev`: no handle is
    /// kept, so its only references are the pending timer's and a queued
    /// recovery's, and it frees itself at the first period after the device
    /// is gone.
    pub fn start_for_device(dev: Weak<dyn NetdevWatchdog>, timeo_ns: u64) {
        drop(Self::start_inner(dev, timeo_ns));
    }

    fn start_inner(dev: Weak<dyn NetdevWatchdog>, timeo_ns: u64) -> Arc<Inner> {
        let inner = Arc::new(Inner {
            timer: TimerList::new(watchdog_timer_fn, 0),
            work: WorkStruct::new(WorkFn::Sync(watchdog_work_fn)),
            dev,
            timeo_jiffies: timer::ns_to_jiffies(timeo_ns).max(1),
            fired: AtomicU64::new(0),
        });
        arm(&inner);
        inner
    }

    /// Recoveries this watchdog queued.
    pub fn fired(&self) -> u64 {
        self.0.fired.load(Ordering::Relaxed)
    }

    /// Whether the watchdog timer is armed.
    pub fn is_armed(&self) -> bool {
        self.0.timer.is_pending()
    }
}

impl Drop for DevWatchdog {
    fn drop(&mut self) {
        // `dev_watchdog_down`: stop the timer and give back its reference.
        if timer::timer_shutdown(&self.0.timer) {
            // SAFETY: the dequeued timer's reference; `self.0` is another.
            unsafe { Arc::decrement_strong_count(Arc::as_ptr(&self.0)) };
        }
    }
}
