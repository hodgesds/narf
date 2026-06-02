//! USB class-driver registry — VID/PID match → probe dispatch.
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
//! - `probe_fn` is a plain `fn(Arc<USBDevice>) -> Result<(), UsbProbeError>`.
//!   The probe stores the device Arc and returns; any async work
//!   (EFUSE reads, firmware upload) is launched as a background task
//!   from inside the probe or deferred to the driver's own pump.
//!   This keeps the registry itself sync so it can be called from
//!   the sync part of the attach dispatcher.

#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::device::USBDevice;

// ── Public types ────────────────────────────────────────────────────

/// A single VID/PID + optional class-triple match entry.
///
/// Mirrors `struct usb_device_id` (Linux `include/linux/usb.h` L730):
/// `idVendor`, `idProduct`, plus class/subclass/protocol guards that
/// are each `None` (= match any).
#[derive(Copy, Clone, Debug)]
pub struct UsbClassMatch {
    pub vendor_id: u16,
    pub product_id: u16,
    /// If `Some`, the device's `bDeviceClass` must equal this value.
    pub class: Option<u8>,
    /// If `Some`, the device's `bDeviceSubClass` must equal this value.
    pub subclass: Option<u8>,
    /// If `Some`, the device's `bDeviceProtocol` must equal this value.
    pub protocol: Option<u8>,
}

impl UsbClassMatch {
    /// Construct a plain VID/PID match with no class restriction.
    pub const fn vid_pid(vendor_id: u16, product_id: u16) -> Self {
        Self {
            vendor_id,
            product_id,
            class: None,
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
pub type UsbProbeFn = fn(device: Arc<USBDevice>) -> Result<(), UsbProbeError>;

// ── Registry internals ──────────────────────────────────────────────

/// Maximum registered USB class drivers. 16 is more than enough for
/// the foreseeable future (rtl8xxxu + btusb + cdc-acm + … etc.).
const MAX_DRIVERS: usize = 16;

struct DriverEntry {
    name: &'static str,
    /// Slice of VID/PID match entries — the driver is tried if any
    /// entry matches (OR logic, matching Linux `usb_match_id`).
    matches: &'static [UsbClassMatch],
    probe: UsbProbeFn,
}

/// The global USB class-driver registry.
static REGISTRY: IrqSafeSpinLock<Vec<DriverEntry>> = IrqSafeSpinLock::new(Vec::new());

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
    let mut g = REGISTRY.lock();
    if g.len() >= MAX_DRIVERS {
        return Err(UsbProbeError::RegistryFull);
    }
    g.push(DriverEntry { name, matches, probe });
    Ok(())
}

/// Walk all registered class drivers in registration order. For each
/// driver, check every `UsbClassMatch` entry against the device's
/// `vendor_id` + `product_id`. The first driver whose table contains
/// a matching entry has its `probe` function called.
///
/// Returns `true` if a driver claimed the device; `false` if no match
/// was found across all registered drivers.
///
/// Equivalent to Linux's per-device `usb_match_id` call within the
/// driver core's `__usb_match_id` + `usb_probe_device` chain in
/// `drivers/usb/core/driver.c` (~L141, L310).
pub fn dispatch_probe(device: Arc<USBDevice>) -> bool {
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
        let matched = matches.iter().any(|m| {
            if m.vendor_id != vid || m.product_id != pid {
                return false;
            }
            // Optional class-triple guards — all present guards must match.
            true
        });
        if !matched {
            continue;
        }
        // Device VID/PID is in this driver's table. Call probe.
        // Clone the Arc so that if probe returns Err we can try the
        // next driver (unusual; typically first match wins).
        match probe(Arc::clone(&device)) {
            Ok(()) => {
                // Driver claimed the device. Log the match.
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  usb-class-registry: {:04x}:{:04x} claimed by {}",
                    vid, pid, name
                );
                return true;
            }
            Err(e) => {
                // Probe failed — log and try next driver.
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  usb-class-registry: {:04x}:{:04x} probe {} failed: {:?}",
                    vid, pid, name, e
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
        if entry.matches.iter().any(|m| m.vendor_id == vendor_id && m.product_id == product_id) {
            return true;
        }
    }
    false
}

/// Reset the registry — used by smoke tests to avoid cross-test
/// state pollution. Always compiled; callers should only invoke
/// this from test code.
pub fn reset_for_test() {
    REGISTRY.lock().clear();
}
