//! PCIe driver-match registry.
//!
//! Each PCIe driver registers a `PciMatch` describing which devices
//! it claims (by exact `(vendor, device)`, by class triple, or by
//! vendor-only) plus a probe function. At boot, a TCB-trusted entry
//! point — `probe_all` — walks `bus::devices()`, finds the first
//! match for each device, mints a `Cap<BusDeviceCap, Write>`, and
//! invokes the probe.
//!
//! This is the bus-level analogue of Linux's `pci_driver` table +
//! `pci_register_driver`. It's distinct from `narf_drivers::Driver`,
//! which models a driver's *lifecycle* (start / quiesce). Match-based
//! probes can either complete synchronously (as the Stage-3 NVMe
//! probe does — bring up the controller and stash it in a static)
//! or hand off to the lifecycle framework.
//!
//! Cap-gating: `probe_all` requires a `Cap<BusRegistryCap, Grant>` —
//! the same authority `claim_device_cap` consults — because issuing
//! probes is the registry-wide action of binding drivers to
//! hardware. Individual probe entries don't need a cap to register
//! (they're statically declared by trusted in-tree drivers); they
//! receive a `Cap<BusDeviceCap, Write>` minted on their behalf.

use alloc::vec::Vec;

use narf_capabilities::{Cap, Grant, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::device::{BusDevice, BusKind};
use crate::registry::{claim_device_cap, devices, BusDeviceCap, BusRegistryCap};

/// Why a probe failed. Drivers return this from their probe fn so
/// `probe_all` can log + continue with the next device, rather than
/// aborting the whole bus walk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Driver couldn't allocate memory needed to bring up the device.
    NoMemory,
    /// Device's cfg-space / BAR layout disagrees with what the driver
    /// expected (firmware bug, wrong device ID, etc.).
    BadDevice,
    /// Generic free-form error message — useful when a probe wants to
    /// surface a one-line reason without a typed variant.
    Other(&'static str),
}

/// Predicate against a `BusDevice`. A `PciMatch` carries one of these
/// plus the probe fn that gets called when the predicate fires.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// Exact `(vendor, device)` pair. Highest specificity — wins over
    /// `Class` / `Vendor` matches when a device matches multiple
    /// entries.
    VendorDevice { vendor: u16, device: u16 },
    /// PCIe base-class match. `class` is the high byte of the class
    /// triple (offset 0x0B); `mask` lets a driver match a class
    /// family (e.g. `class=0x01, mask=0xFF` = "all storage").
    Class { class: u8, mask: u8 },
    /// Match every device of a vendor. Lowest specificity.
    Vendor { vendor: u16 },
}

impl MatchKind {
    /// `true` iff `device` matches this kind.
    pub fn matches(&self, device: &BusDevice) -> bool {
        // Match-based dispatch only makes sense for PCIe devices —
        // virtio-mmio uses its own discovery shape.
        if !matches!(device.kind, BusKind::Pcie { .. }) {
            return false;
        }
        match *self {
            MatchKind::VendorDevice {
                vendor,
                device: dev,
            } => device.id.vendor == vendor && device.id.device == dev,
            MatchKind::Class { class, mask } => {
                let dev_class = ((device.id.class >> 16) & 0xFF) as u8;
                (dev_class & mask) == (class & mask)
            }
            MatchKind::Vendor { vendor } => device.id.vendor == vendor,
        }
    }

    /// Specificity rank — higher means "more specific." Used by
    /// `probe_all` to break ties when a device matches multiple
    /// entries; the more specific one wins.
    pub fn specificity(&self) -> u8 {
        match self {
            MatchKind::VendorDevice { .. } => 3,
            MatchKind::Class { .. } => 2,
            MatchKind::Vendor { .. } => 1,
        }
    }
}

/// Driver probe signature. The driver receives the discovered device
/// + a freshly-minted authority cap, and returns success / a typed
/// error. The cap is owned by the probe — it can stash it in a
/// static, hand it to a long-lived task, etc.
pub type PciProbeFn =
    fn(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError>;

/// One entry in the driver-match registry.
#[derive(Copy, Clone)]
pub struct PciMatch {
    /// Human-readable driver name. Used in diagnostics + as a
    /// duplicate-registration key.
    pub name: &'static str,
    /// Predicate against discovered devices.
    pub kind: MatchKind,
    /// Probe fn invoked when a matching device is discovered.
    pub probe: PciProbeFn,
}

impl core::fmt::Debug for PciMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PciMatch")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Backing store for registered drivers. Wave-3a single global
/// list — registration is a boot-time event, so a `IrqSafeSpinLock`
/// is fine.
static REGISTRY: IrqSafeSpinLock<Vec<PciMatch>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver with the match table. Idempotent on `name` —
/// re-registering replaces the prior entry, so the test harness
/// can drive multiple smokes that re-add the same driver without
/// leaking entries.
pub fn register(m: PciMatch) {
    let mut g = REGISTRY.lock();
    if let Some(pos) = g.iter().position(|e| e.name == m.name) {
        g[pos] = m;
    } else {
        g.push(m);
    }
}

/// Snapshot of currently-registered drivers. The bus crate clones
/// out of the lock so callers can iterate without holding it.
pub fn registered() -> Vec<PciMatch> {
    REGISTRY.lock().clone()
}

/// Number of registered drivers — handy for tests + diagnostics.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Walk every device in the bus registry, find the highest-specificity
/// matching `PciMatch`, mint a `Cap<BusDeviceCap, Write>`, and invoke
/// the probe. Returns the count of probes that returned `Ok(())`.
///
/// Probes that error are logged via `log_probe_failure` (Wave 3a stub)
/// and the walk continues. A device with no matching driver is
/// silently skipped — drivers can be loaded later, and a re-run of
/// `probe_all` will pick it up.
pub fn probe_all(
    authority: &Cap<BusRegistryCap, Grant>,
) -> Result<u32, narf_capabilities::CapError> {
    authority.check_live()?;
    let drivers = registered();
    let devs = devices();
    let mut bound = 0u32;

    for d in &devs {
        // Find the most specific matching driver.
        let mut best: Option<&PciMatch> = None;
        for m in &drivers {
            if m.kind.matches(d) {
                best = Some(match best {
                    None => m,
                    Some(prev) if m.kind.specificity() > prev.kind.specificity() => m,
                    Some(prev) => prev,
                });
            }
        }
        let Some(m) = best else {
            continue;
        };

        // Mint the per-device cap. We're inside a TCB-trusted
        // entry point (probe_all itself is cap-gated), so calling
        // claim_device_cap with our authority is the canonical
        // path.
        let (_handle, cap) = match claim_device_cap(authority, d.addr) {
            Ok(ok) => ok,
            Err(e) => {
                let _ = e;
                continue;
            }
        };
        match (m.probe)(*d, cap) {
            Ok(()) => bound += 1,
            Err(e) => log_probe_failure(m, d, e),
        }
    }
    Ok(bound)
}

/// Probe-failure observability hook. Wave-3a stub: drops the
/// failure on the floor (the kernel-test harness can call into the
/// per-driver static state to verify success). Wave-3b can route
/// this through `tracing/` once the trace probe IDs land.
fn log_probe_failure(_m: &PciMatch, _d: &BusDevice, _e: ProbeError) {}

#[doc(hidden)]
/// Test-only: reset the registry between smokes. Keeps tests
/// hermetic without exposing a public clear path.
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}
