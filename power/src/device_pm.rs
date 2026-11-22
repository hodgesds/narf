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
/// The trait mirrors Linux's `struct dev_pm_ops`: `.suspend` and `.resume`
/// for S3 and s2idle (`drivers/base/power/main.c::dpm_suspend_start`), and
/// hibernation's `.freeze`, `.thaw`, `.poweroff` and `.restore`. Those four
/// default as `SET_SYSTEM_SLEEP_PM_OPS` sets them: freeze and poweroff are
/// the suspend, thaw and restore the resume.
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
    /// `PMSG_FREEZE`: quiesce before the hibernation snapshot. Reverse order.
    fn freeze(&self) -> Result<(), DevicePmError> {
        self.suspend()
    }
    /// `PMSG_THAW`: after the snapshot, so the image can be written, or
    /// after a failed one ([`hibernate_is_recovering`]). Forward order.
    fn thaw(&self) -> Result<(), DevicePmError> {
        self.resume()
    }
    /// `PMSG_HIBERNATE`: before the platform's S4 entry. Reverse order.
    fn poweroff(&self) -> Result<(), DevicePmError> {
        self.suspend()
    }
    /// `PMSG_RESTORE`: in the restored image. Forward order.
    fn restore(&self) -> Result<(), DevicePmError> {
        self.resume()
    }
}
/// The hibernation callbacks of a function-pointer registration
/// ([`register_device_pm_hibernation`]); without them, a
/// [`register_device_pm`] entry's freeze and poweroff run its suspend and
/// its thaw and restore run its resume.
#[derive(Clone, Copy, Debug)]
pub struct HibernationFns {
    pub freeze: PmFn,
    pub thaw: PmFn,
    pub poweroff: PmFn,
    pub restore: PmFn,
}
/// Which `dev_pm_ops` callback a fan-out runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Suspend,
    Resume,
    Freeze,
    Thaw,
    Poweroff,
    Restore,
}
impl Phase {
    /// Quiescing phases run children before parents.
    fn reverse(self) -> bool {
        matches!(self, Phase::Suspend | Phase::Freeze | Phase::Poweroff)
    }
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
    /// The fn-pointer form's hibernation callbacks, if it has its own.
    pub hibernation: Option<HibernationFns>,
}
impl DevicePmEntry {
    fn run(&self, phase: Phase) -> Result<(), DeviceSuspendError> {
        if let Some(ops) = self.ops.as_ref() {
            return match phase {
                Phase::Suspend => ops.suspend(),
                Phase::Resume => ops.resume(),
                Phase::Freeze => ops.freeze(),
                Phase::Thaw => ops.thaw(),
                Phase::Poweroff => ops.poweroff(),
                Phase::Restore => ops.restore(),
            };
        }
        let h = self.hibernation;
        match phase {
            Phase::Suspend => (self.suspend)(),
            Phase::Resume => (self.resume)(),
            Phase::Freeze => h.map_or(self.suspend, |h| h.freeze)(),
            Phase::Thaw => h.map_or(self.resume, |h| h.thaw)(),
            Phase::Poweroff => h.map_or(self.suspend, |h| h.poweroff)(),
            Phase::Restore => h.map_or(self.resume, |h| h.restore)(),
        }
    }
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
    /// The system suspend orchestrator must abort and resume devices when
    /// any callback returns Busy (for example an active DMUB transaction).
    Busy,
    /// Driver cannot quiesce for system suspend. The orchestrator must abort
    /// rather than powering down an active device.
    NotImplemented,
}

static REGISTRY: IrqSafeSpinLock<Vec<DevicePmEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver's suspend/resume callbacks. Idempotent on
/// `name` — re-registering replaces the prior entry so a driver
/// can re-probe itself without doubling its registry footprint.
/// Registration order matters: earlier = closer-to-bus-root.
/// Suspend runs in reverse; resume in forward order.
pub fn register_device_pm(name: &str, suspend: PmFn, resume: PmFn) {
    register_entry(DevicePmEntry {
        name: String::from(name),
        suspend,
        resume,
        ops: None,
        hibernation: None,
    });
}
/// [`register_device_pm`] with the driver's own hibernation callbacks
/// (a driver whose thaw must not resume, as amdgpu's does not).
pub fn register_device_pm_hibernation(
    name: &str,
    suspend: PmFn,
    resume: PmFn,
    hibernation: HibernationFns,
) {
    register_entry(DevicePmEntry {
        name: String::from(name),
        suspend,
        resume,
        ops: None,
        hibernation: Some(hibernation),
    });
}
fn register_entry(entry: DevicePmEntry) {
    let mut g = REGISTRY.lock();
    let name = entry.name.clone();
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
        hibernation: None,
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

/// Withdraw a detached device; release the driver's Arc outside the registry lock.
pub fn unregister_device_pm(name: &str) -> bool {
    let removed = {
        let mut registry = REGISTRY.lock();
        registry
            .iter()
            .position(|e| e.name == name)
            .map(|i| registry.remove(i))
    };
    removed.is_some()
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
/// plus a count of failures so the caller can decide whether to
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
    fan_out(Phase::Suspend)
}
/// `dpm_suspend(PMSG_FREEZE)` before the hibernation snapshot, in reverse
/// registration order.
pub fn freeze_all_devices() -> FanoutReport {
    fan_out(Phase::Freeze)
}
/// `dpm_resume(PMSG_THAW)` after the snapshot, or after a failed image
/// with [`set_hibernate_recovering`] set, in forward order.
pub fn thaw_all_devices() -> FanoutReport {
    fan_out(Phase::Thaw)
}
/// `dpm_suspend_start(PMSG_HIBERNATE)` before the platform's S4 entry, in
/// reverse order.
pub fn poweroff_all_devices() -> FanoutReport {
    fan_out(Phase::Poweroff)
}
/// `dpm_resume(PMSG_RESTORE)` in the restored image, in forward order.
pub fn restore_all_devices() -> FanoutReport {
    fan_out(Phase::Restore)
}
/// One pass over a registry snapshot; no failure stops it.
fn fan_out(phase: Phase) -> FanoutReport {
    let snap = REGISTRY.lock().clone();
    let mut outcomes = Vec::with_capacity(snap.len());
    let mut failure_count = 0;
    let mut run = |entry: &DevicePmEntry| {
        let result = entry.run(phase);
        if result.is_err() {
            failure_count += 1;
        }
        outcomes.push(DeviceFanoutOutcome {
            name: entry.name.clone(),
            result,
        });
    };
    if phase.reverse() {
        snap.iter().rev().for_each(&mut run);
    } else {
        snap.iter().for_each(&mut run);
    }
    FanoutReport {
        outcomes,
        failure_count,
    }
}

/// `pm_hibernate_is_recovering`: a thaw after the snapshot or the image
/// write failed, so the devices must come back for the running system.
static RECOVERING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub fn set_hibernate_recovering(recovering: bool) {
    RECOVERING.store(recovering, core::sync::atomic::Ordering::Release);
}
pub fn hibernate_is_recovering() -> bool {
    RECOVERING.load(core::sync::atomic::Ordering::Acquire)
}

/// Call every registered resume handler in **forward**
/// registration order.
pub fn resume_all_devices() -> FanoutReport {
    fan_out(Phase::Resume)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}

/// Temporarily isolate a synchronous smoke from probe-owned PM registrations.
/// Restores the original entries, their order and retained operations on every
/// return path. Fixtures must keep the guard alive for their whole fan-out.
#[doc(hidden)]
pub fn __test_isolate_registry() -> TestRegistryGuard {
    TestRegistryGuard(core::mem::take(&mut *REGISTRY.lock()))
}

#[doc(hidden)]
#[derive(Debug)]
#[must_use]
pub struct TestRegistryGuard(Vec<DevicePmEntry>);

impl Drop for TestRegistryGuard {
    fn drop(&mut self) {
        let fixtures = core::mem::replace(&mut *REGISTRY.lock(), core::mem::take(&mut self.0));
        // Test operations may have a re-entrant Drop, just like real drivers.
        drop(fixtures);
    }
}

fn smoke_device_pm_unregister_drops_outside_registry_lock() -> narf_kernel_test::TestResult {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DROPPED: AtomicBool = AtomicBool::new(false);
    #[derive(Debug)]
    struct Model;
    impl DevicePmOps for Model {
        fn suspend(&self) -> Result<(), DevicePmError> {
            Ok(())
        }
        fn resume(&self) -> Result<(), DevicePmError> {
            Ok(())
        }
    }
    impl Drop for Model {
        fn drop(&mut self) {
            let _ = device_count();
            DROPPED.store(true, Ordering::Release);
        }
    }
    DROPPED.store(false, Ordering::Release);
    register_device_pm_ops("test-igc-detach", Arc::new(Model));
    if !unregister_device_pm("test-igc-detach")
        || !DROPPED.load(Ordering::Acquire)
        || unregister_device_pm("test-igc-detach")
    {
        return narf_kernel_test::TestResult::Fail("PM withdrawal lifetime failed");
    }
    narf_kernel_test::TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "power",
    smoke_device_pm_unregister_drops_outside_registry_lock
);
