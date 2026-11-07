//! AMD MP2 ISP camera coprocessor — explicit refusal marker (#811).
//!
//! The MP2 ISP bring-up is NOT implemented: there is no firmware
//! load of `amd/amdmp2.bin`, no SFH IPC camera command pipe, and no
//! CSI/sensor bring-up. Probe therefore declines every MP2 device
//! with `ProbeError::NotForThisDriver` *before touching the
//! hardware* (no PCI command enable, no BAR2 map, no bound-driver
//! record, no video node), so the device is never presented as bound
//! and stays available to the next claimant in the bus arbitration
//! walk (bus spec §9.3). This replaces the earlier probe-shaped
//! stub, which mapped BAR2, recorded a bound driver, and logged
//! "probed" for a camera that could never stream.
//!
//! Declining has a welcome side effect for the shared MP2 function:
//! the AMD SFH sensor-hub driver matches the same two device IDs,
//! and with this scaffold no longer claiming the function first,
//! SFH can probe it in the same walk. The arbitration itself is
//! tracked in #1046 and is untouched here — this lane only stops
//! claiming what it cannot drive.
//!
//! Per-platform scoping lives in [`refusal_reason`]: each MP2
//! generation gets its own reason. Full firmware/CSI bring-up is
//! out of scope here; it needs Daniel's hardware confirmation
//! (Renoir/Phoenix internal webcams are unconfirmed USB-vs-ISP,
//! #811).
//!
//! The AMD MP2 (Multi-Processor 2) is a general-purpose coprocessor
//! embedded in Ryzen SoCs. Depending on the SoC variant it also
//! serves as the camera ISP and sensor-hub bridge.
//!
//! ## References (Linux GPL, post 2026-05-20 relicense)
//!
//! - `linux/drivers/hid/amd-sfh-hid/amd_sfh_common.h`:
//!   `PCI_DEVICE_ID_AMD_MP2 = 0x15E4`,
//!   `PCI_DEVICE_ID_AMD_MP2_1_1 = 0x164A`.
//! - `linux/drivers/hid/amd-sfh-hid/amd_sfh_pcie.c`:
//!   `amd_mp2_pci_probe`, two-entry `amd_mp2_pci_tbl`.
//! - AMD public SFH (Sensor Fusion Hub) firmware documentation.
//!
//! ## PCI identity
//!
//! | Vendor | Device | SoC generation            |
//! |--------|--------|---------------------------|
//! | 0x1022 | 0x15E4 | Renoir / Cezanne (MP2 1.0)|
//! | 0x1022 | 0x164A | Van Gogh / Phoenix (MP2 1.1)|
//!
//! Note: The task brief cited 1022:14E9 but that maps to a register
//! offset in amdgpu, not a PCI device ID. The authoritative PCI IDs
//! from Linux's AMD SFH driver are 0x15E4 and 0x164A.
//!
//! ## Firmware
//!
//! AMD ships a firmware blob in the linux-firmware repository. The
//! canonical name this driver resolves is `amd/amdmp2.bin`
//! (consistent with how AMD SFH firmware is packaged alongside the
//! amdgpu blobs). Stage-1 resolved and logged the name; Stage-2
//! would load it via the firmware registry. Until then probe
//! refuses (see above) and the [`Camera`] methods below are
//! unreachable — no instance can exist without a successful probe.

use narf_driver_runtime::{BusDevice, BusDeviceCap, Cap, Write};

use crate::{BufferQueue, Camera, CameraError, PixelFormat, Result};

// ── PCI IDs ──────────────────────────────────────────────────────────

/// AMD vendor ID.
pub const AMD_VENDOR: u16 = 0x1022;

// Source: linux/drivers/hid/amd-sfh-hid/amd_sfh_common.h
/// MP2 1.0 — Renoir / Cezanne SoCs.
pub const MP2_DID_15E4: u16 = 0x15E4;
/// MP2 1.1 — Van Gogh / Phoenix SoCs.
pub const MP2_DID_164A: u16 = 0x164A;

/// All recognized AMD MP2 ISP (vendor, device) pairs, for testing.
pub const PCI_IDS: &[(u16, u16)] = &[(AMD_VENDOR, MP2_DID_15E4), (AMD_VENDOR, MP2_DID_164A)];

// ── Firmware blob name ───────────────────────────────────────────────

/// Firmware blob resolved at probe time and logged so the firmware
/// registry knows what to pre-cache before Stage-2 loads it.
/// Consistent with AMD SFH firmware packaging conventions.
/// Still unresolved today: probe refuses before any load is
/// attempted, and the name survives only as the per-generation
/// scoping datum for [`refusal_reason`].
pub const FIRMWARE_NAME: &str = "amd/amdmp2.bin";

// ── Refusal reason (per-platform scoping, #811) ───────────────────

/// Why probe refuses this MP2 device ID, naming the generation and
/// the firmware blob that has no loader yet.
///
/// Returns `None` for unknown device IDs. The two generations get
/// distinct reasons so a refusal for a Renoir part cannot be
/// mistaken for a Phoenix one.
pub fn refusal_reason(did: u16) -> Option<&'static str> {
    match Mp2Gen::from_did(did)? {
        Mp2Gen::Mp2V1 => Some(
            "amd-mp2-isp (Renoir/Cezanne, MP2 1.0, firmware amd/amdmp2.bin): \
             no firmware load and no SFH IPC camera bring-up yet; declining \
             leaves the shared MP2 function available to the AMD SFH driver (#811)",
        ),
        Mp2Gen::Mp2V1_1 => Some(
            "amd-mp2-isp (Van Gogh/Phoenix, MP2 1.1, firmware amd/amdmp2.bin): \
             no firmware load and no SFH IPC camera bring-up yet; declining \
             leaves the shared MP2 function available to the AMD SFH driver (#811)",
        ),
    }
}

// ── Driver state ────────────────────────────────────────────────────

/// MP2 ISP generation identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mp2Gen {
    /// MP2 1.0 — Renoir / Cezanne.
    Mp2V1,
    /// MP2 1.1 — Van Gogh / Phoenix.
    Mp2V1_1,
}

impl Mp2Gen {
    fn from_did(did: u16) -> Option<Self> {
        match did {
            MP2_DID_15E4 => Some(Mp2Gen::Mp2V1),
            MP2_DID_164A => Some(Mp2Gen::Mp2V1_1),
            _ => None,
        }
    }
}

/// Probed AMD MP2 ISP instance.
///
/// Unreachable while [`probe`] refuses: no instance can exist
/// without a successful probe. Kept as the Stage-2 skeleton.
#[derive(Debug)]
pub struct AmdMp2Isp {
    /// Vendor ID (always `AMD_VENDOR`).
    pub vid: u16,
    /// Device ID.
    pub did: u16,
    /// MP2 generation.
    pub gen: Mp2Gen,
    /// Firmware blob name to load at Stage-2.
    pub firmware_name: &'static str,
    /// MMIO region for the MP2 ISP register window (BAR2).
    pub regs: narf_driver_runtime::MmioRegion,
    /// Buffer queue for camera capture frames.
    queue: BufferQueue,
}

impl Camera for AmdMp2Isp {
    fn buffer_queue(&self) -> &BufferQueue {
        &self.queue
    }

    fn buffer_queue_mut(&mut self) -> &mut BufferQueue {
        &mut self.queue
    }

    fn set_format(&self, _fmt: PixelFormat, _w: u32, _h: u32) -> Result<()> {
        // Unreachable while probe refuses (#811): no instance can
        // exist without firmware loaded and the SFH command pipe online.
        // Stage-2 configures the output format via SFH IPC.
        Err(CameraError::NotImplemented)
    }

    fn start_streaming(&self) -> Result<()> {
        // Unreachable while probe refuses (#811). Stage-2 sends
        // CAMERA_START via AMD SFH IPC.
        Err(CameraError::NotImplemented)
    }

    fn stop_streaming(&self) -> Result<()> {
        // Unreachable while probe refuses (#811).
        Err(CameraError::NotImplemented)
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static CONTROLLER: narf_lib::sync::IrqSafeSpinLock<Option<AmdMp2Isp>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return `true` if an AMD MP2 ISP was successfully probed at boot.
///
/// Always `false` while probe refuses (#811); kept as the
/// observable "never bound" predicate for tests and for Stage-2.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// PCI probe entry-point — explicit refusal (#811).
///
/// Declines every known MP2 device with
/// `ProbeError::NotForThisDriver` *before touching the hardware*:
/// no PCI command enable, no BAR2 map, no singleton install, no
/// bound-driver record. The bus dispatcher returns the device to
/// the candidate list so another driver — in practice the AMD SFH
/// sensor-hub driver, which matches the same two IDs — may claim
/// it (bus spec §9.3; arbitration tracked in #1046, untouched
/// here). The per-generation reason is logged so the refusal is
/// visible on boot instead of silent; unknown IDs decline
/// silently as before.
///
/// # Safety
///
/// Exclusive BAR access held by the bus probe framework. No BAR is
/// touched while refusing, so this is vacuous today; Stage-2
/// re-enables the mapping and the contract applies again.
pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> core::result::Result<(), narf_bus::ProbeError> {
    if device.id.vendor != AMD_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let reason = refusal_reason(device.id.device).ok_or(narf_bus::ProbeError::NotForThisDriver)?;

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  amd-mp2-isp: refusing 0x{:04X}:0x{:04X} — {}",
            device.id.vendor,
            device.id.device,
            reason,
        );
    }

    Err(narf_bus::ProbeError::NotForThisDriver)
}

/// Register AMD MP2 ISP with the PCI bus.
///
/// The matches stay registered so the bus framework routes each
/// MP2 device to [`probe`], which declines it honestly with the
/// per-generation reason — removing the matches would leave the
/// device silently unclaimed with no trace of the refusal.
pub fn register_pci_driver() {
    for &(vendor, device) in PCI_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "amd-mp2-isp",
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}
