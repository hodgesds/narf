//! Bound-driver inventory.
//!
//! Each driver records `(name, kind, vendor, device, bound_at_cycles)`
//! when its probe completes successfully, so the framework can give
//! observers + tooling a uniform answer to "which drivers are running
//! and against which devices?"
//!
//! The PCIe match registry (`bus::driver_match`) tracks *registered
//! intent* — what driver wants to bind which match-pattern. This
//! crate's `bound::registry` tracks *outcomes* — what's actually
//! running. The two stay independent so a probe failure doesn't
//! corrupt the intent table.

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BoundKind {
    /// Block storage (NVMe, AHCI, virtio-blk, …).
    Block,
    /// Network interface controller.
    Net,
    /// USB host controller.
    UsbHost,
    /// Random-number-generator source.
    Rng,
    /// Memory-pressure / ballooning device.
    Balloon,
    /// Catch-all for things that don't fit a class yet.
    Other,
}

impl BoundKind {
    /// Default isolation domain for drivers of this kind. Domain 0
    /// (`FRAME`) is reserved for the kernel TCB; classes are
    /// assigned 1..=15 by category. Multiple drivers of the same
    /// kind share a domain — the design's unit of isolation is the
    /// *category*, not the individual device.
    ///
    /// Mapping:
    ///   * Block       → 1
    ///   * Net         → 2
    ///   * UsbHost     → 3
    ///   * Rng         → 4
    ///   * Balloon     → 5
    ///   * Other       → 15  (the catch-all bucket)
    pub const fn default_domain(self) -> u8 {
        match self {
            BoundKind::Block   => 1,
            BoundKind::Net     => 2,
            BoundKind::UsbHost => 3,
            BoundKind::Rng     => 4,
            BoundKind::Balloon => 5,
            BoundKind::Other   => 15,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BoundDriver {
    /// Driver-side short name (e.g. "nvme0", "vblk0", "e1000-82540em").
    pub name:     String,
    pub kind:     BoundKind,
    /// PCI vendor / device IDs the probe matched, when applicable.
    /// `None` for non-PCI drivers.
    pub pci_vid:  Option<u16>,
    pub pci_did:  Option<u16>,
    /// Isolation domain assigned to this driver. Defaults to
    /// `kind.default_domain()` at registration; can be overridden
    /// via `set_domain` for explicit placement.
    pub domain:   u8,
}

static BOUND: IrqSafeSpinLock<Vec<BoundDriver>> =
    IrqSafeSpinLock::new(Vec::new());

/// Record a successful bind. Idempotent on `name` — re-binding
/// replaces the prior entry.
pub fn record(b: BoundDriver) {
    let mut g = BOUND.lock();
    if let Some(pos) = g.iter().position(|e| e.name == b.name) {
        g[pos] = b;
    } else {
        g.push(b);
    }
}

/// Snapshot of currently-bound drivers.
pub fn snapshot() -> Vec<BoundDriver> { BOUND.lock().clone() }

/// Number of bound drivers.
pub fn count() -> usize { BOUND.lock().len() }

/// Override the isolation domain of an already-bound driver. Returns
/// `true` if the driver was found and updated. Callers typically
/// invoke this only when a deployment policy needs a non-default
/// placement (e.g. partitioning multiple block drivers across
/// distinct domains for blast-radius reasons).
pub fn set_domain(name: &str, domain: u8) -> bool {
    let mut g = BOUND.lock();
    if let Some(e) = g.iter_mut().find(|e| e.name == name) {
        e.domain = domain & 0xF; // domains are 0..=15
        true
    } else {
        false
    }
}

/// Look up the assigned domain of a bound driver by name.
pub fn domain_of(name: &str) -> Option<u8> {
    BOUND.lock().iter().find(|e| e.name == name).map(|e| e.domain)
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() { BOUND.lock().clear(); }
