//! The periodic driver watchdog as delayed work.
//!
//! Linux Realtek drivers run their dynamic-mechanism step from a work that
//! re-queues itself: rtw88 `rtw_watch_dog_work` (`RTW_WATCH_DOG_DELAY_TIME`),
//! rtlwifi `rtl_watch_dog_timer_callback` → `rtl_watchdog_wq_callback`
//! (`RTL_WATCH_DOG_TIME`), rtl8xxxu `rtl8xxxu_watchdog_callback`
//! (`schedule_delayed_work(&priv->ra_watchdog, 2 * HZ)`). The device state
//! the step touches is shared under the device's own mutex, as Linux's
//! `priv` is under its mutexes; the work only holds the device weakly.
//!
//! [`start`] leaks one [`WatchdogWork`] per device. Each run upgrades the
//! device, runs its step and re-queues; once the device is gone or reports
//! itself withdrawn the run frees the work instead (the
//! `cancel_delayed_work_sync` of the Linux stop path, from the work's side).

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::{future::Future, pin::Pin};
use narf_scheduler::workqueue::{
    queue_delayed_work, system_wq, DelayedWork, WorkFn, WorkFuture, WorkRef,
};

/// A device whose watchdog step runs from [`WatchdogWork`].
pub(crate) trait Watchdog: Send + Sync + 'static {
    /// The device has been withdrawn: the work stops re-queueing.
    fn watchdog_stopped(&self) -> bool;
    /// One watchdog period's step. The future owns the device for its run.
    fn watchdog_step(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The device's watchdog delayed work.
#[repr(C)]
struct WatchdogWork<D: Watchdog> {
    /// First field: the work function's `WorkRef` is this struct.
    dw: DelayedWork,
    device: Weak<D>,
    /// The re-queue delay in jiffies.
    period: u64,
}

/// Queue `device`'s watchdog every `period_ms`, the first run one period
/// from now. The work lives until a run finds the device stopped.
pub(crate) fn start<D: Watchdog>(device: &Arc<D>, period_ms: u64) {
    start_jiffies(
        device,
        narf_time::timer::ns_to_jiffies(period_ms.saturating_mul(1_000_000)),
    );
}

/// [`start`] with the period in jiffies (tests use a short one).
pub(crate) fn start_jiffies<D: Watchdog>(device: &Arc<D>, period: u64) {
    let work = Box::leak(Box::new(WatchdogWork {
        dw: DelayedWork::new(WorkFn::Async(run::<D>), false),
        device: Arc::downgrade(device),
        period,
    }));
    queue(work);
}

fn queue<D: Watchdog>(work: &WatchdogWork<D>) {
    // SAFETY: the work is leaked and only its own last run frees it, which
    // it does only when it does not re-queue; it is never queued elsewhere.
    unsafe { queue_delayed_work(system_wq(), &work.dw, work.period) };
}

fn run<D: Watchdog>(r: WorkRef) -> WorkFuture {
    let addr = r.as_ptr() as usize;
    // SAFETY: only `WatchdogWork<D>` uses `run::<D>`; its delayed work
    // (whose `work` is first) is its first field, and it is alive until
    // this run frees it.
    let device = unsafe { &*(addr as *const WatchdogWork<D>) }
        .device
        .upgrade();
    Box::pin(async move {
        // `addr` (a usize, not a pointer) is what lives across the await.
        match device {
            Some(device) if !device.watchdog_stopped() => {
                device.watchdog_step().await;
                // SAFETY: as above; this path does not free the work.
                queue(unsafe { &*(addr as *const WatchdogWork<D>) });
            }
            device => {
                drop(device);
                // SAFETY: neither pending nor queued (this run is the last
                // and does not re-queue), and the pool never touches a work
                // after calling its function: the work is ours to free.
                drop(unsafe { Box::from_raw(addr as *mut WatchdogWork<D>) });
            }
        }
    })
}

#[cfg(feature = "kernel-test")]
#[path = "watchdog_work_tests.rs"]
mod tests;
