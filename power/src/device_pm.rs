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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use narf_lib::sync::IrqSafeSpinLock;

/// Suspend / resume handler signature. Driver-supplied,
/// no-arg, no-state — handlers reach into their own per-device
/// statics for the work.
pub type PmFn = fn() -> Result<(), DeviceSuspendError>;

/// Trait variant of the per-device suspend/resume hooks. Drivers
/// whose suspend/resume needs to carry per-device state (saved
/// PCI config, MMIO snapshot, controller-specific shadow regs)
/// implement this and register via [`register_device_pm_ops`].
///
/// The trait mirrors Linux's `struct dev_pm_ops` (`.suspend` and
/// `.resume` callbacks; see `drivers/base/power/main.c::dpm_suspend_start`),
/// minus the freeze/poweroff/restore quartet — NARF only supports
/// the S3 "suspend → resume" pair today. When hibernate (S4) lands
/// we extend this with `freeze` / `thaw` / `poweroff` / `restore`.
///
/// Object-safe: `Arc<dyn DevicePmOps>` is what the registry holds.
/// Handlers run on the boot CPU with interrupts gated — they MUST
/// NOT schedule, sleep on the scheduler, or call back into power.
pub trait DevicePmOps: Send + Sync {
    /// Quiesce the device. Called in reverse-registration order
    /// during S3 entry. Failures don't abort the suspend chain —
    /// the aggregator counts them.
    fn suspend(&self) -> Result<(), DevicePmError>;
    /// Re-arm the device. Called in forward-registration order
    /// from the wake continuation.
    fn resume(&self) -> Result<(), DevicePmError>;
}

/// Error variants returned from a `DevicePmOps` callback. Alias
/// of [`DeviceSuspendError`] kept distinct so trait impls don't
/// have to import the suspend-fan-out type when only registering
/// device PM. They're identical at the wire level.
pub type DevicePmError = DeviceSuspendError;

/// One driver's suspend/resume handlers. Either the fn-pointer
/// pair OR the trait object is populated; the fan-out picks
/// whichever is present (trait wins if both are set — should
/// never happen in practice because `register_device_pm` and
/// `register_device_pm_ops` are dispatched on `name`).
#[derive(Clone)]
pub struct DevicePmEntry {
    pub name: String,
    pub suspend: PmFn,
    pub resume: PmFn,
    /// Trait-object form. When present, takes precedence over
    /// the fn-pointer fields above.
    pub ops: Option<Arc<dyn DevicePmOps>>,
}

impl fmt::Debug for DevicePmEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevicePmEntry")
            .field("name", &self.name)
            .field("has_ops", &self.ops.is_some())
            .finish_non_exhaustive()
    }
}

/// What can go wrong inside a per-device suspend/resume callback.
/// The fan-out aggregates these — one failure doesn't abort the
/// rest of the chain (we still want to save what we can).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceSuspendError {
    /// Handler returned an error specific to its driver.
    /// Used by `nvme` (controller didn't acknowledge the shutdown
    /// notification) and `xhci` (Run/Stop bit didn't latch).
    DriverError,
    /// Device is in a state that doesn't allow suspending right now
    /// (active uninterruptible transfer, firmware mid-load, etc.).
    /// Used by the test harness to validate per-device-failure
    /// aggregation; no production driver returns this yet.
    Busy,
    /// Driver doesn't support suspend yet — fall through to S0i3 /
    /// freeze without touching this device. Scaffolding for drivers
    /// that need to opt out of S3 quiesce; not used today (all
    /// registered drivers — nvme, xhci, amdgpu — implement real
    /// suspend/resume). Kept so the fan-out aggregator's caller can
    /// pattern-match on the full set without churning the variant
    /// list when the first opt-out driver lands.
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
        ops: None,
    };
    if let Some(slot) = g.iter_mut().find(|e| e.name == name) {
        *slot = entry;
    } else {
        g.push(entry);
    }
}

/// Register a driver via the [`DevicePmOps`] trait object. Used
/// when the driver needs to carry per-device state across
/// suspend/resume (e.g. a saved PCI config snapshot, an MMIO
/// shadow, a controller queue depth). Idempotent on `name`.
///
/// The trait object is stored as `Arc<dyn DevicePmOps>`; the
/// fan-out clones a fresh `Arc` before invoking the callback so
/// the registry lock isn't held across the device call.
pub fn register_device_pm_ops(name: &str, ops: Arc<dyn DevicePmOps>) {
    let mut g = REGISTRY.lock();
    // Stub fn-pointers that should never be called — the trait
    // takes precedence in the fan-out.
    fn unreachable_suspend() -> Result<(), DeviceSuspendError> {
        Err(DeviceSuspendError::DriverError)
    }
    fn unreachable_resume() -> Result<(), DeviceSuspendError> {
        Err(DeviceSuspendError::DriverError)
    }
    let entry = DevicePmEntry {
        name: String::from(name),
        suspend: unreachable_suspend,
        resume: unreachable_resume,
        ops: Some(ops),
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
        let result = if let Some(ops) = entry.ops.as_ref() {
            ops.suspend()
        } else {
            (entry.suspend)()
        };
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
        let result = if let Some(ops) = entry.ops.as_ref() {
            ops.resume()
        } else {
            (entry.resume)()
        };
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
