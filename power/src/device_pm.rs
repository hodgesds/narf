//! Device power-management registry.
//!
//! Drivers register a `(name, suspend_fn, resume_fn)` triple at
//! probe time. The S3 phase machinery fans out:
//!
//! - **`suspend_all_devices`** — calls every registered `suspend_fn`
//!   in **reverse** registration order. Reverse so dependents
//!   (e.g. a USB hub driver) quiesce before the controller they
//!   depend on (xHCI). This matches Linux's device-tree teardown
//!   order.
//!
//! - **`resume_all_devices`** — calls every `resume_fn` in
//!   **forward** registration order. Controllers come up before
//!   the devices that hang off them.
//!
//! Each handler is a `fn() -> Result<(), DeviceSuspendError>`.
//! Handlers run on the boot CPU with interrupts already gated
//! (the suspend phase quiesces user CPUs first); they must not
//! schedule or sleep on the scheduler.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// Suspend / resume handler signature. Driver-supplied,
/// no-arg, no-state — handlers reach into their own per-device
/// statics for the work.
pub type PmFn = fn() -> Result<(), DeviceSuspendError>;

/// One driver's suspend/resume handlers.
#[derive(Clone, Debug)]
pub struct DevicePmEntry {
    pub name: String,
    pub suspend: PmFn,
    pub resume: PmFn,
}

/// What can go wrong inside a per-device suspend/resume callback.
/// The fan-out aggregates these — one failure doesn't abort the
/// rest of the chain (we still want to save what we can).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceSuspendError {
    /// Handler returned an error specific to its driver.
    DriverError,
    /// Device is in a state that doesn't allow suspending right now
    /// (active uninterruptible transfer, firmware mid-load, etc.).
    Busy,
    /// Driver doesn't support suspend yet — fall through to S0i3 /
    /// freeze without touching this device.
    NotImplemented,
}

static REGISTRY: IrqSafeSpinLock<Vec<DevicePmEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver's suspend/resume callbacks. Idempotent on
/// `name` — re-registering replaces the prior entry so a driver
/// can re-probe itself without doubling its registry footprint.
/// Registration order matters: earlier = closer-to-bus-root.
/// Suspend runs in reverse; resume in forward order.
pub fn register_device_pm(name: &str, suspend: PmFn, resume: PmFn) {
    let mut g = REGISTRY.lock();
    let entry = DevicePmEntry {
        name: String::from(name),
        suspend,
        resume,
    };
    if let Some(slot) = g.iter_mut().find(|e| e.name == name) {
        *slot = entry;
    } else {
        g.push(entry);
    }
}

/// Snapshot of the registry — primarily for diagnostics / the
/// boot log.
pub fn registered_devices() -> Vec<DevicePmEntry> {
    REGISTRY.lock().clone()
}

/// Number of registered devices.
pub fn device_count() -> usize {
    REGISTRY.lock().len()
}

/// One device's outcome from a fan-out pass. Aggregated into
/// [`FanoutReport`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceFanoutOutcome {
    pub name: String,
    pub result: Result<(), DeviceSuspendError>,
}

/// Result of a suspend or resume fan-out — per-device outcomes
/// + a count of failures so the caller can decide whether to
/// abort the surrounding phase machinery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FanoutReport {
    pub outcomes: Vec<DeviceFanoutOutcome>,
    pub failure_count: usize,
}

impl FanoutReport {
    pub fn ok(&self) -> bool {
        self.failure_count == 0
    }
}

/// Call every registered suspend handler in **reverse**
/// registration order. One device's failure doesn't abort the
/// chain — we want partial progress so resume can roll back as
/// much as possible.
pub fn suspend_all_devices() -> FanoutReport {
    let snap = REGISTRY.lock().clone();
    let mut outcomes = Vec::with_capacity(snap.len());
    let mut failure_count = 0;
    for entry in snap.iter().rev() {
        let result = (entry.suspend)();
        if result.is_err() {
            failure_count += 1;
        }
        outcomes.push(DeviceFanoutOutcome {
            name: entry.name.clone(),
            result,
        });
    }
    FanoutReport {
        outcomes,
        failure_count,
    }
}

/// Call every registered resume handler in **forward**
/// registration order.
pub fn resume_all_devices() -> FanoutReport {
    let snap = REGISTRY.lock().clone();
    let mut outcomes = Vec::with_capacity(snap.len());
    let mut failure_count = 0;
    for entry in snap.iter() {
        let result = (entry.resume)();
        if result.is_err() {
            failure_count += 1;
        }
        outcomes.push(DeviceFanoutOutcome {
            name: entry.name.clone(),
            result,
        });
    }
    FanoutReport {
        outcomes,
        failure_count,
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}
