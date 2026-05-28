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
    /// Human-input device (keyboard, mouse, touchpad, virtio-input).
    Input,
    /// Display / framebuffer (bochs, virtio-gpu, ramfb).
    Graphics,
    /// PCM audio playback / capture (virtio-sound, hda, ac97).
    Audio,
    /// Camera ISP / media coprocessor (Intel IPU, AMD MP2 ISP).
    Media,
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
    ///   * Input       → 6
    ///   * Graphics    → 7
    ///   * Audio       → 8
    ///   * Media       → 9
    ///   * Other       → 15  (the catch-all bucket)
    pub const fn default_domain(self) -> u8 {
        match self {
            BoundKind::Block => 1,
            BoundKind::Net => 2,
            BoundKind::UsbHost => 3,
            BoundKind::Rng => 4,
            BoundKind::Balloon => 5,
            BoundKind::Input => 6,
            BoundKind::Graphics => 7,
            BoundKind::Audio => 8,
            BoundKind::Media => 9,
            BoundKind::Other => 15,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BoundDriver {
    /// Driver-side short name (e.g. "nvme0", "vblk0", "e1000-82540em").
    pub name: String,
    pub kind: BoundKind,
    /// PCI vendor / device IDs the probe matched, when applicable.
    /// `None` for non-PCI drivers.
    pub pci_vid: Option<u16>,
    pub pci_did: Option<u16>,
    /// Isolation domain assigned to this driver. Defaults to
    /// `kind.default_domain()` at registration; can be overridden
    /// via `set_domain` for explicit placement.
    pub domain: u8,
}

/// Firmware-version coupling for a bound driver. Captured at the
/// moment the driver successfully consumed a `Cap<FirmwareBlob,
/// Read>` from the registry. Stored in a side table indexed by
/// driver name so the public `BoundDriver` struct stays
/// struct-literal-compatible across the existing bind sites.
#[derive(Clone, Debug)]
pub struct BoundFirmware {
    /// Canonical name of the blob (e.g. "qcom/qcnfa765/amss.bin").
    pub blob_name: String,
    /// Digest of the firmware payload.
    pub sha256: [u8; 32],
    /// Signer fingerprint, when the blob was signed.
    pub signer: Option<[u8; 32]>,
    /// Vendor-supplied version string, when the trailer carried one.
    pub version: Option<String>,
}

static BOUND: IrqSafeSpinLock<Vec<BoundDriver>> = IrqSafeSpinLock::new(Vec::new());

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
pub fn snapshot() -> Vec<BoundDriver> {
    BOUND.lock().clone()
}

/// Number of bound drivers.
pub fn count() -> usize {
    BOUND.lock().len()
}

/// Side table of firmware-version couplings, indexed by driver
/// name. Set via `set_firmware`; queried via `firmware_of`. Kept
/// out of `BoundDriver` so the existing struct-literal bind sites
/// don't need an extra field.
static BOUND_FIRMWARE: IrqSafeSpinLock<Vec<(String, BoundFirmware)>> =
    IrqSafeSpinLock::new(Vec::new());

/// Record the firmware blob a driver loaded. Replaces any prior
/// firmware entry on the same driver (re-loads pick up new
/// versions on rebind). Returns `true` if the driver is in the
/// bound-driver inventory; the firmware entry is stored
/// regardless so a future `set_firmware`-then-`record` ordering
/// is also supported.
pub fn set_firmware(name: &str, fw: BoundFirmware) -> bool {
    let mut g = BOUND_FIRMWARE.lock();
    if let Some(e) = g.iter_mut().find(|(n, _)| n == name) {
        e.1 = fw;
    } else {
        g.push((alloc::string::String::from(name), fw));
    }
    BOUND.lock().iter().any(|d| d.name == name)
}

/// Look up the firmware coupling recorded for `driver_name`, if any.
pub fn firmware_of(driver_name: &str) -> Option<BoundFirmware> {
    BOUND_FIRMWARE
        .lock()
        .iter()
        .find(|(n, _)| n == driver_name)
        .map(|(_, fw)| fw.clone())
}

/// Snapshot of every recorded firmware coupling. Used by
/// observability for the kernel system-state report.
pub fn firmware_snapshot() -> Vec<(String, BoundFirmware)> {
    BOUND_FIRMWARE.lock().clone()
}

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
    BOUND
        .lock()
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.domain)
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    BOUND.lock().clear();
}
