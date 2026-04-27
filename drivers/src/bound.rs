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

#[derive(Clone, Debug)]
pub struct BoundDriver {
    /// Driver-side short name (e.g. "nvme0", "vblk0", "e1000-82540em").
    pub name:     String,
    pub kind:     BoundKind,
    /// PCI vendor / device IDs the probe matched, when applicable.
    /// `None` for non-PCI drivers.
    pub pci_vid:  Option<u16>,
    pub pci_did:  Option<u16>,
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

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() { BOUND.lock().clear(); }
