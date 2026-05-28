//! AMD MP2 ISP camera coprocessor driver scaffold — Stage-0/1.
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
//! amdgpu blobs). Stage-1 resolves and logs the name; Stage-2 loads
//! it via the firmware registry.
//!
//! ## Stage-1 scope
//!
//! 1. Claim the PCIe device via exact VID:DID match.
//! 2. Map BAR2 (MP2 register window — the SFH/ISP MMIO aperture).
//! 3. Resolve and log the firmware blob name.
//! 4. Record a bound-driver entry.

extern crate alloc;

use narf_driver_runtime::{map_bar, BusDevice, BusDeviceCap, Cap, Write};

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
pub const PCI_IDS: &[(u16, u16)] = &[
    (AMD_VENDOR, MP2_DID_15E4),
    (AMD_VENDOR, MP2_DID_164A),
];

// ── Firmware blob name ───────────────────────────────────────────────

/// Firmware blob resolved at probe time and logged so the firmware
/// registry knows what to pre-cache before Stage-2 loads it.
/// Consistent with AMD SFH firmware packaging conventions.
pub const FIRMWARE_NAME: &str = "amd/amdmp2.bin";

// ── BAR layout ───────────────────────────────────────────────────────

/// BAR2: MP2 ISP register window (MMIO aperture).
/// The SFH driver in Linux maps BAR2 for the ISP/sensor-hub MMIO.
const BAR_REGS: u8 = 2;

// ── Driver state ─────────────────────────────────────────────────────

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
        // Stage-2: configure MP2 ISP output format via SFH IPC.
        // Requires firmware loaded and SFH command pipe online.
        Err(CameraError::NotImplemented)
    }

    fn start_streaming(&self) -> Result<()> {
        // Stage-2: send CAMERA_START via AMD SFH IPC.
        Err(CameraError::NotImplemented)
    }

    fn stop_streaming(&self) -> Result<()> {
        Err(CameraError::NotImplemented)
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static CONTROLLER: narf_lib::sync::IrqSafeSpinLock<Option<AmdMp2Isp>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return `true` if an AMD MP2 ISP was successfully probed at boot.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// PCI probe entry-point.
///
/// # Safety
///
/// Exclusive BAR access held by the bus probe framework.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> core::result::Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    if device.id.vendor != AMD_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let gen = Mp2Gen::from_did(device.id.device)
        .ok_or(narf_bus::ProbeError::NotForThisDriver)?;

    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // Map BAR2: MP2 ISP register window.
    // SAFETY: exclusive BAR ownership held by bus probe contract.
    let regs = unsafe { map_bar(&device, BAR_REGS) }
        .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let isp = AmdMp2Isp {
        vid: device.id.vendor,
        did: device.id.device,
        gen,
        firmware_name: FIRMWARE_NAME,
        regs,
        queue: BufferQueue::new(),
    };

    *CONTROLLER.lock() = Some(isp);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("amd-mp2-isp"),
        kind: narf_drivers::BoundKind::Media,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Media.default_domain(),
    });

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  amd-mp2-isp: probed (0x{:04X}:0x{:04X}, gen {:?}), firmware={}",
            device.id.vendor,
            device.id.device,
            gen,
            FIRMWARE_NAME,
        );
    }

    Ok(())
}

/// Register AMD MP2 ISP with the PCI bus.
pub fn register_pci_driver() {
    for &(vendor, device) in PCI_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "amd-mp2-isp",
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}
