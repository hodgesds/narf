//! USB class-driver registry — VID/PID or interface-class match →
//! probe dispatch.
//!
//! Equivalent to Linux's `usb_register_driver` /
//! `usb_match_id` pattern. A class driver registers a
//! `(name, matches[], probe_fn)` tuple at Stage::Subsys; the xHCI
//! enumeration dispatcher calls `dispatch_probe` after Configure
//! Endpoint and the first matching driver's `probe` function is
//! invoked with an `Arc<USBDevice>`.
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/usb/core/driver.c::usb_register_driver` (L967) —
//!   walks the bus and calls `probe` for each matching device.
//! - `drivers/usb/core/driver.c::usb_match_id` (L141) —
//!   compares `(idVendor, idProduct)` against a `usb_device_id`
//!   table; class/subclass/protocol matching also supported.
//!
//! ## Design
//!
//! - Registry is a global `IrqSafeSpinLock<Vec<_>>` capped at
//!   `MAX_DRIVERS` entries. Held only during registration and the
//!   initial VID/PID scan, never across a `.await`.
//! - `probe_fn` is a plain sync fn. The probe stores the device Arc
//!   and returns; any async work (EFUSE reads, firmware upload) is
//!   launched as a background task from inside the probe or
//!   deferred to the driver's own pump. This keeps the registry
//!   itself sync so it can be called from the sync part of the
//!   attach dispatcher. Probes additionally receive the device's
//!   hub context (`Some((parent hub slot, downstream port))` when
//!   the device sits behind a hub, `None` on a root port) so
//!   drivers that participate in hub idle-suspend can record it
//!   and later resume their own port.
//! - Suspend hooks (`UsbSuspendFn`) are the one async registry
//!   entry. They run inside the supervisor's async
//!   `idle_suspend_pass`, which is polled by the executor, so a
//!   sync hook bridging with `block_on` would panic (executor
//!   re-entry guard). Hooks therefore return a boxed future and
//!   `dispatch_suspend` awaits them in registration order before
//!   the pass gates the port.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use narf_lib::sync::IrqSafeSpinLock;

use crate::device::USBDevice;

// ── Public types ────────────────────────────────────────────────────

/// A single VID/PID + optional interface-class-triple match entry.
///
/// Mirrors `struct usb_device_id` (Linux `include/linux/usb.h` L730):
/// `idVendor`, `idProduct`, plus class/subclass/protocol guards that
/// are each `None` (= match any).
#[derive(Copy, Clone, Debug)]
pub struct UsbClassMatch {
    pub vendor_id: u16,
    pub product_id: u16,
    /// If `Some`, a configuration interface's `bInterfaceClass` must
    /// equal this value.
    pub class: Option<u8>,
    /// If `Some`, that interface's `bInterfaceSubClass` must equal this
    /// value.
    pub subclass: Option<u8>,
    /// If `Some`, that interface's `bInterfaceProtocol` must equal this
    /// value.
    pub protocol: Option<u8>,
}

impl UsbClassMatch {
    pub const fn vid_pid(vendor_id: u16, product_id: u16) -> Self {
        Self {
            vendor_id,
            product_id,
            class: None,
            subclass: None,
            protocol: None,
        }
    }

    /// Construct a class-only interface match. A zero VID/PID pair is
    /// reserved here as the explicit wildcard; USB VID 0 is not
    /// assignable to a physical device.
    pub const fn class_only(class: u8) -> Self {
        Self {
            vendor_id: 0,
            product_id: 0,
            class: Some(class),
            subclass: None,
            protocol: None,
        }
    }
}

/// Error returned by a USB class driver's probe function.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UsbProbeError {
    /// Device matched but the driver could not bind (e.g. endpoint
    /// descriptors missing, OOM on state allocation).
    BindFailed,
    /// Device matched but the chip/firmware variant is unsupported.
    UnsupportedVariant,
    /// The registry was full; registration was rejected.
    RegistryFull,
}

/// Probe function signature — synchronous. The function stores the
/// `Arc<USBDevice>` handle internally and returns `Ok(())` if the
/// driver has claimed the device. Any async init work is spawned
/// separately. `Err(UsbProbeError)` releases the device claim and
/// the dispatcher continues to the next registered driver.
///
/// `hub_port` is the device's hub context: `Some((parent hub slot
/// id, downstream port))` when the device sits behind a hub,
/// `None` when it is on a root port. Drivers that participate in
/// hub idle-suspend (currently the USB NICs) record it at bind;
/// drivers that do not participate ignore it. The slot id is a
/// hub slot id, never a `HUBS` index (see #892).
pub type UsbProbeFn =
    fn(device: Arc<USBDevice>, hub_port: Option<(u8, u8)>) -> Result<(), UsbProbeError>;

/// Outcome of a class suspend hook for one hub port, reported to
/// [`dispatch_suspend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspendOutcome {
    /// This hook owns no live device on the port; nothing parked.
    NotMine,
    /// The hook parked its device (datapath parked, wakeup arming
    /// attempted; see the driver's hook for its arming semantics).
    /// The pass may gate the port.
    Parked,
    /// The hook owns a live device on the port but could not park
    /// it (e.g. the wake-filter programming failed and gating
    /// would leave the device unable to wake). The pass must NOT
    /// gate the port this cycle; it retries next cycle.
    ParkFailed,
}

/// Outcome of [`dispatch_suspend`]: how many hooks ran, how many
/// parked a device, and how many failed to park. Gating proceeds
/// only when `failed == 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspendReport {
    /// Hooks invoked for this port (including NotMine ones).
    pub invoked: usize,
    /// Hooks that parked a device on the port.
    pub parked: usize,
    /// Hooks that own a live device on the port but failed to park.
    pub failed: usize,
}

/// Future returned by a suspend hook.
pub type SuspendFuture = Pin<Box<dyn Future<Output = SuspendOutcome> + Send>>;

/// Suspend hook signature — async, returning a boxed future (see
/// the module docs: a sync hook could not bridge to transfers
/// from inside the supervisor's executor poll). Called with the
/// controller index, parent hub's slot id and downstream port number, for a port
/// the supervisor's idle-suspend pass is about to gate. The hook
/// self-filters: it parks only a live (non-detached) device whose
/// recorded context equals `(controller, hub_slot, port)`, and returns
/// [`SuspendOutcome::NotMine`] otherwise. It must be idempotent
/// (an already-parked device returns `Parked` without re-arming)
/// and panic-free (see the [`UsbUnbindFn`] contract: panic is
/// fatal by policy). It must never hold its record lock across an
/// `.await`: lock to find, release, transfer, lock to set flags.
pub type UsbSuspendFn = fn(controller: u8, hub_slot: u8, port: u8) -> SuspendFuture;

/// Unbind function signature — synchronous. Called with the controller
/// index ([`crate::xhci::Xhci::id`]) and slot id of a device being
/// detached (unplug / supervisor teardown); slot ids are only unique
/// within a controller. The driver drops any binding it holds for that
/// controller/slot; drivers that
/// never bound it must no-op. A driver registers an unbind hook via
/// [`register_class_driver_with_unbind`]; without one, detach
/// cannot reach the driver's private state (its slot is still
/// disabled and reclaimed by the dispatcher).
///
/// Failure contract (#893): a hook reports failure with `Err(())`
/// instead of panicking, and [`dispatch_unbind`] continues past
/// failed hooks — one hook's failure must never abort detach for
/// every class. A hook that PANICS cannot be contained: the
/// kernel builds with `panic = "abort"` and no unwinding, so a
/// panicking hook is fatal by policy, exactly like a panic
/// anywhere else in the kernel. Hooks must therefore be written
/// panic-free (no indexing, no `unwrap`/`expect` on fallible
/// paths) and idempotent: registration tolerates duplicates
/// (defensive test initcalls re-register), so a hook may run
/// twice for one dispatch and must still leave state consistent.
pub type UsbUnbindFn = fn(controller: u8, slot_id: u8) -> Result<(), ()>;

/// Outcome of [`dispatch_unbind`]: how many hooks ran, and how
/// many reported failure. Detach proceeds regardless of the
/// failure count; the report exists so tests and the supervisor
/// can observe hook health without a hook failure wedging detach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnbindReport {
    /// Hooks invoked for this slot (including failed ones).
    pub invoked: usize,
    /// Hooks that returned `Err(())`.
    pub failed: usize,
}

// ── Registry internals ──────────────────────────────────────────────

/// Bound the class-driver/hook inventory, not the number of USB devices.
/// The in-tree Ethernet, wireless and peripheral families have outgrown the
/// original 16-entry budget once diagnostic hooks are registered as well.
const MAX_DRIVERS: usize = 32;

struct DriverEntry {
    name: &'static str,
    /// Slice of VID/PID match entries — the driver is tried if any
    /// entry matches (OR logic, matching Linux `usb_match_id`).
    matches: &'static [UsbClassMatch],
    probe: UsbProbeFn,
    /// Optional detach hook, invoked by `dispatch_unbind`.
    unbind: Option<UsbUnbindFn>,
}

/// The global USB class-driver registry.
static REGISTRY: IrqSafeSpinLock<Vec<DriverEntry>> = IrqSafeSpinLock::new(Vec::new());

struct SuspendEntry {
    name: &'static str,
    hook: UsbSuspendFn,
}

/// The global class suspend-hook registry. Separate from
/// [`REGISTRY`]: suspend hooks are addressed by hub port, not by
/// VID/PID match, and they run in the supervisor's idle-suspend
/// pass rather than at attach time.
static SUSPEND_HOOKS: IrqSafeSpinLock<Vec<SuspendEntry>> = IrqSafeSpinLock::new(Vec::new());

// ── Public API ──────────────────────────────────────────────────────

/// Register a USB class driver. Called at Stage::Subsys before any
/// device appears. The `matches` slice is a static array of
/// `UsbClassMatch` entries; first match against a newly-enumerated
/// device triggers `probe`.
///
/// Returns `Ok(())` on success, `Err(UsbProbeError::RegistryFull)` if
/// `MAX_DRIVERS` is reached.
///
/// Linux analogue: `usb_register_driver` in
/// `drivers/usb/core/driver.c` (L967).
pub fn register_class_driver(
    name: &'static str,
    matches: &'static [UsbClassMatch],
    probe: UsbProbeFn,
) -> Result<(), UsbProbeError> {
    register_class_driver_inner(name, matches, probe, None)
}

/// Register a USB class driver together with its detach hook. The
/// hook is called by [`dispatch_unbind`] whenever any device is
/// detached, with that device's slot id. The hook contract is on
/// [`UsbUnbindFn`]: report failure with `Err(())`, never panic,
/// and be idempotent (registration tolerates duplicates).
pub fn register_class_driver_with_unbind(
    name: &'static str,
    matches: &'static [UsbClassMatch],
    probe: UsbProbeFn,
    unbind: UsbUnbindFn,
) -> Result<(), UsbProbeError> {
    register_class_driver_inner(name, matches, probe, Some(unbind))
}

fn register_class_driver_inner(
    name: &'static str,
    matches: &'static [UsbClassMatch],
    probe: UsbProbeFn,
    unbind: Option<UsbUnbindFn>,
) -> Result<(), UsbProbeError> {
    let mut g = REGISTRY.lock();
    // Registration tolerates duplicates (defensive test initcalls
    // re-register, and a full boot already registered every driver
    // from the Stage::Subsys initcalls): a second registration
    // under the same name is a no-op success, so duplicates never
    // consume `MAX_DRIVERS` slots and crowd later drivers out with
    // a spurious `RegistryFull`.
    if g.iter().any(|entry| entry.name == name) {
        return Ok(());
    }
    if g.len() >= MAX_DRIVERS {
        return Err(UsbProbeError::RegistryFull);
    }
    g.push(DriverEntry {
        name,
        matches,
        probe,
        unbind,
    });
    Ok(())
}

/// Register a class suspend hook. Called at Stage::Subsys
/// alongside the driver's class registration. Registration
/// tolerates duplicates (defensive test initcalls re-register),
/// so hooks must be idempotent; a duplicate run for an
/// already-parked device returns `Parked` without re-arming.
/// Returns `Err(UsbProbeError::RegistryFull)` past `MAX_DRIVERS`
/// hooks.
pub fn register_suspend_hook(name: &'static str, hook: UsbSuspendFn) -> Result<(), UsbProbeError> {
    let mut g = SUSPEND_HOOKS.lock();
    if g.iter().any(|entry| entry.name == name) {
        return Ok(());
    }
    if g.len() >= MAX_DRIVERS {
        return Err(UsbProbeError::RegistryFull);
    }
    g.push(SuspendEntry { name, hook });
    Ok(())
}

/// Invoke every registered suspend hook for one hub port, in
/// registration order, awaiting each before running the next.
/// Hooks self-filter by `(controller, hub_slot, port)` against their own
/// records. A `ParkFailed` outcome is counted and dispatch
/// CONTINUES with the remaining hooks (same isolation rule as
/// [`dispatch_unbind`]): one hook's failure must never skip
/// another hook's park. The caller — the supervisor's
/// idle-suspend pass — gates the port only when the report's
/// `failed` count is zero; a failed park means some live device
/// on the port is unparked, and gating would break its datapath
/// with no resume path. Ports claimed by no hook gate exactly as
/// before (the HID behavior: no hook, no park step, gate as
/// today).
pub async fn dispatch_suspend(controller: u8, hub_slot: u8, port: u8) -> SuspendReport {
    let hooks: Vec<UsbSuspendFn> = {
        let g = SUSPEND_HOOKS.lock();
        g.iter().map(|entry| entry.hook).collect()
    };
    let mut report = SuspendReport {
        invoked: 0,
        parked: 0,
        failed: 0,
    };
    for hook in hooks {
        report.invoked += 1;
        match hook(controller, hub_slot, port).await {
            SuspendOutcome::NotMine => {}
            SuspendOutcome::Parked => report.parked += 1,
            SuspendOutcome::ParkFailed => report.failed += 1,
        }
    }
    report
}

/// Invoke every registered driver's unbind hook for `slot_id` on
/// `controller`
/// (broadcast: hooks self-filter, since the registry does not track
/// which driver claimed which slot). Hooks run after the registry
/// lock is released, so a hook may itself touch the registry or
/// class state. A hook that returns `Err(())` is counted and
/// dispatch CONTINUES with the remaining hooks (#893): one
/// hook's failure must never abort detach for every class, and
/// `detach_slot` proceeds to disable/reclaim the slot
/// regardless of this report. (A hook that panics cannot be
/// contained — see [`UsbUnbindFn`]: panic is fatal by policy.)
pub fn dispatch_unbind(controller: u8, slot_id: u8) -> UnbindReport {
    let hooks: alloc::vec::Vec<UsbUnbindFn> = {
        let g = REGISTRY.lock();
        g.iter().filter_map(|entry| entry.unbind).collect()
    };
    let mut report = UnbindReport {
        invoked: 0,
        failed: 0,
    };
    for hook in hooks {
        report.invoked += 1;
        if hook(controller, slot_id).is_err() {
            report.failed += 1;
        }
    }
    report
}

/// Return whether one match entry accepts this device. A non-zero
/// VID/PID pair is exact; `(0, 0)` is the explicit class-only
/// wildcard. Class/subclass/protocol guards are evaluated against
/// Interface Descriptors in `config`, never against the device-level
/// class triple.
pub(crate) fn match_entry(
    entry: &UsbClassMatch,
    vendor_id: u16,
    product_id: u16,
    config: &[u8],
) -> bool {
    let ids_match = (entry.vendor_id == 0 && entry.product_id == 0)
        || (entry.vendor_id == vendor_id && entry.product_id == product_id);
    if !ids_match {
        return false;
    }

    if entry.class.is_none() && entry.subclass.is_none() && entry.protocol.is_none() {
        return true;
    }

    let mut offset = 0usize;
    while offset + 2 <= config.len() {
        let len = config[offset] as usize;
        if len < 2 || offset + len > config.len() {
            break;
        }
        if config[offset + 1] == 0x04 && len >= 9 {
            let class_matches = entry.class.is_none_or(|class| class == config[offset + 5]);
            let subclass_matches = entry
                .subclass
                .is_none_or(|subclass| subclass == config[offset + 6]);
            let protocol_matches = entry
                .protocol
                .is_none_or(|protocol| protocol == config[offset + 7]);
            if class_matches && subclass_matches && protocol_matches {
                return true;
            }
        }
        offset += len;
    }
    false
}

/// Walk all registered class drivers in registration order. For each
/// driver, check every [`UsbClassMatch`] entry against the device's
/// VID/PID and its Configuration Descriptor. The first driver whose
/// table contains a matching entry has its `probe` function called
/// with the device and its hub context.
///
/// Returns `true` if a driver claimed the device; `false` if no match
/// was found across all registered drivers.
///
/// Equivalent to Linux's per-device `usb_match_id` call within the
/// driver core's `__usb_match_id` + `usb_probe_device` chain in
/// `drivers/usb/core/driver.c` (~L141, L310).
pub fn dispatch_probe(device: Arc<USBDevice>, config: &[u8], hub_port: Option<(u8, u8)>) -> bool {
    let vid = device.vendor_id();
    let pid = device.product_id();

    // Collect the (name, matches, probe) tuples under the lock, then
    // release before calling any probe function so the probe can
    // itself call register_class_driver or acquire other locks.
    // Capped at MAX_DRIVERS; the allocation is bounded.
    let snapshot: Vec<(&'static str, &'static [UsbClassMatch], UsbProbeFn)> = {
        let g = REGISTRY.lock();
        g.iter().map(|e| (e.name, e.matches, e.probe)).collect()
    };

    for (name, matches, probe) in snapshot {
        let matched = matches
            .iter()
            .any(|entry| match_entry(entry, vid, pid, config));
        if !matched {
            continue;
        }
        // Device VID/PID is in this driver's table. Call probe.
        // Clone the Arc so that if probe returns Err we can try the
        // next driver (unusual; typically first match wins).
        match probe(Arc::clone(&device), hub_port) {
            Ok(()) => {
                // Driver claimed the device. Log the match.
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  usb-class-registry: {:04x}:{:04x} claimed by {}",
                    vid,
                    pid,
                    name
                );
                return true;
            }
            Err(e) => {
                // Probe failed — log and try next driver.
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  usb-class-registry: {:04x}:{:04x} probe {} failed: {:?}",
                    vid,
                    pid,
                    name,
                    e
                );
                // Continue to next driver (unusual but allowed).
            }
        }
    }
    false
}

/// Return the number of currently registered class drivers.
/// Mainly useful for smoke tests.
pub fn registered_count() -> usize {
    REGISTRY.lock().len()
}

/// Walk registered drivers and return whether any driver's match table
/// contains `(vendor_id, product_id)`. Does NOT call `probe` — used
/// only to test the VID/PID matching logic without needing a live
/// `Arc<USBDevice>`.
pub fn would_match(vendor_id: u16, product_id: u16) -> bool {
    let g = REGISTRY.lock();
    for entry in g.iter() {
        if entry
            .matches
            .iter()
            .any(|m| m.vendor_id == vendor_id && m.product_id == product_id)
        {
            return true;
        }
    }
    false
}

/// Reset the registry — used by smoke tests to avoid cross-test
/// state pollution. Always compiled; callers should only invoke
/// this from test code. Clears the suspend-hook registry as well.
pub fn reset_for_test() {
    REGISTRY.lock().clear();
    SUSPEND_HOOKS.lock().clear();
}
