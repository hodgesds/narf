//! Intel IPU6 Image Signal Processor driver scaffold — Stage-0/1.
//!
//! ## References (Linux GPL, post 2026-05-20 relicense)
//!
//! - `linux/include/media/ipu6-pci-table.h` — all IPU6 PCI device IDs.
//! - `linux/drivers/media/pci/intel/ipu6/ipu6.h` — firmware blob names.
//! - `linux/drivers/media/pci/intel/ipu6/ipu6.c` — probe + firmware
//!   selection by device ID, BAR mapping.
//!
//! ## PCI ID table
//!
//! | Variant      | Vendor | Device  | Platform          | Firmware blob           |
//! |--------------|--------|---------|-------------------|-------------------------|
//! | IPU6         | 0x8086 | 0x9A19  | Tiger Lake        | intel/ipu/ipu6_fw.bin   |
//! | IPU6SE       | 0x8086 | 0x4E19  | Jasper Lake       | intel/ipu/ipu6se_fw.bin |
//! | IPU6EP (ADL) | 0x8086 | 0x465D  | Alder Lake-P      | intel/ipu/ipu6ep_fw.bin |
//! | IPU6EP (RPL) | 0x8086 | 0xA75D  | Raptor Lake-P     | intel/ipu/ipu6ep_fw.bin |
//! | IPU6EP (ADN) | 0x8086 | 0x462E  | Alder Lake-N      | intel/ipu/ipu6epadln_fw.bin |
//! | IPU6EP (MTL) | 0x8086 | 0x7D19  | Meteor Lake       | intel/ipu/ipu6epmtl_fw.bin |
//!
//! ## Stage-1 scope
//!
//! 1. Claim the PCIe device (exact VID:DID match per entry above).
//! 2. Map BAR0 (IPU6 register / MMIO aperture).
//! 3. Resolve firmware blob name for this device ID and log it.
//! 4. Record a bound-driver entry.
//!
//! Firmware loading requires the IPU6 Complex Peripheral Device (CPD)
//! image parser (`ipu6-cpd.c`) and is deferred to Stage-2.

extern crate alloc;

use narf_driver_runtime::{map_bar, BusDevice, BusDeviceCap, Cap, Write};

use crate::{BufferQueue, Camera, CameraError, PixelFormat, Result};

// ── PCI IDs ──────────────────────────────────────────────────────────

/// Intel vendor ID.
pub const INTEL_VENDOR: u16 = 0x8086;

// Source: linux/include/media/ipu6-pci-table.h
/// IPU6 — Tiger Lake.
pub const IPU6_DID: u16 = 0x9A19;
/// IPU6SE — Jasper Lake.
pub const IPU6SE_DID: u16 = 0x4E19;
/// IPU6EP — Alder Lake-P.
pub const IPU6EP_ADLP_DID: u16 = 0x465D;
/// IPU6EP — Raptor Lake-P.
pub const IPU6EP_RPLP_DID: u16 = 0xA75D;
/// IPU6EP — Alder Lake-N.
pub const IPU6EP_ADLN_DID: u16 = 0x462E;
/// IPU6EP — Meteor Lake.
pub const IPU6EP_MTL_DID: u16 = 0x7D19;

/// All recognized IPU6 (vendor, device) pairs, for testing.
pub const PCI_IDS: &[(u16, u16)] = &[
    (INTEL_VENDOR, IPU6_DID),
    (INTEL_VENDOR, IPU6SE_DID),
    (INTEL_VENDOR, IPU6EP_ADLP_DID),
    (INTEL_VENDOR, IPU6EP_RPLP_DID),
    (INTEL_VENDOR, IPU6EP_ADLN_DID),
    (INTEL_VENDOR, IPU6EP_MTL_DID),
];

// ── Firmware blob names ──────────────────────────────────────────────
//
// Source: linux/drivers/media/pci/intel/ipu6/ipu6.h
//   #define IPU6_FIRMWARE_NAME      "intel/ipu/ipu6_fw.bin"
//   #define IPU6SE_FIRMWARE_NAME    "intel/ipu/ipu6se_fw.bin"
//   #define IPU6EP_FIRMWARE_NAME    "intel/ipu/ipu6ep_fw.bin"
//   #define IPU6EPADLN_FIRMWARE_NAME "intel/ipu/ipu6epadln_fw.bin"
//   #define IPU6EPMTL_FIRMWARE_NAME  "intel/ipu/ipu6epmtl_fw.bin"
//
/// Firmware blob name for IPU6 (Tiger Lake).
pub const FW_IPU6: &str = "intel/ipu/ipu6_fw.bin";
/// Firmware blob name for IPU6SE (Jasper Lake).
pub const FW_IPU6SE: &str = "intel/ipu/ipu6se_fw.bin";
/// Firmware blob name for IPU6EP (Alder Lake-P / Raptor Lake-P).
pub const FW_IPU6EP: &str = "intel/ipu/ipu6ep_fw.bin";
/// Firmware blob name for IPU6EP (Alder Lake-N).
pub const FW_IPU6EP_ADLN: &str = "intel/ipu/ipu6epadln_fw.bin";
/// Firmware blob name for IPU6EP (Meteor Lake).
pub const FW_IPU6EP_MTL: &str = "intel/ipu/ipu6epmtl_fw.bin";

/// Resolve the firmware blob name for a given IPU6 device ID.
///
/// Returns `None` for unknown device IDs (shouldn't happen after
/// the exact-match table filters, but guards against future IDs).
pub const fn firmware_for(did: u16) -> Option<&'static str> {
    match did {
        IPU6_DID => Some(FW_IPU6),
        IPU6SE_DID => Some(FW_IPU6SE),
        IPU6EP_ADLP_DID | IPU6EP_RPLP_DID => Some(FW_IPU6EP),
        IPU6EP_ADLN_DID => Some(FW_IPU6EP_ADLN),
        IPU6EP_MTL_DID => Some(FW_IPU6EP_MTL),
        _ => None,
    }
}

/// IPU6 variant identifier (mirrors `ipu6_hw_variants` in Linux).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ipu6Variant {
    Ipu6,
    Ipu6Se,
    Ipu6Ep,
    Ipu6EpAdln,
    Ipu6EpMtl,
}

impl Ipu6Variant {
    fn from_did(did: u16) -> Option<Self> {
        match did {
            IPU6_DID => Some(Ipu6Variant::Ipu6),
            IPU6SE_DID => Some(Ipu6Variant::Ipu6Se),
            IPU6EP_ADLP_DID | IPU6EP_RPLP_DID => Some(Ipu6Variant::Ipu6Ep),
            IPU6EP_ADLN_DID => Some(Ipu6Variant::Ipu6EpAdln),
            IPU6EP_MTL_DID => Some(Ipu6Variant::Ipu6EpMtl),
            _ => None,
        }
    }
}

// ── BAR layout ───────────────────────────────────────────────────────

/// BAR0: IPU6 register window (MMIO).
/// Source: ipu6.c `pci_iomap(isp->pdev, 0, ...)`.
const BAR_REGS: u8 = 0;

// ── Driver state ─────────────────────────────────────────────────────

/// Probed IPU6 instance.
#[derive(Debug)]
pub struct Ipu6 {
    /// Vendor ID (always `INTEL_VENDOR`).
    pub vid: u16,
    /// Device ID — distinguishes Tiger Lake vs Alder Lake etc.
    pub did: u16,
    /// IPU6 hardware variant.
    pub variant: Ipu6Variant,
    /// Name of the firmware blob that needs to be loaded.
    pub firmware_name: &'static str,
    /// MMIO region for the IPU6 register window (BAR0).
    pub regs: narf_driver_runtime::MmioRegion,
    /// Buffer queue for camera capture frames.
    queue: BufferQueue,
}

impl Camera for Ipu6 {
    fn buffer_queue(&self) -> &BufferQueue {
        &self.queue
    }

    fn buffer_queue_mut(&mut self) -> &mut BufferQueue {
        &mut self.queue
    }

    fn set_format(&self, _fmt: PixelFormat, _w: u32, _h: u32) -> Result<()> {
        // Stage-2: program ISYS format via IPU6 firmware IPC.
        // Requires firmware loaded, ISYS streams configured.
        Err(CameraError::NotImplemented)
    }

    fn start_streaming(&self) -> Result<()> {
        // Stage-2: send STREAM_START IPC message to IPU6 firmware.
        Err(CameraError::NotImplemented)
    }

    fn stop_streaming(&self) -> Result<()> {
        Err(CameraError::NotImplemented)
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static CONTROLLER: narf_lib::sync::IrqSafeSpinLock<Option<Ipu6>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return `true` if an IPU6 was successfully probed at boot.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Probe function for all IPU6 device IDs.
///
/// # Safety
///
/// Exclusive BAR access must be held by the bus probe framework.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> core::result::Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    if device.id.vendor != INTEL_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let variant =
        Ipu6Variant::from_did(device.id.device).ok_or(narf_bus::ProbeError::NotForThisDriver)?;
    let firmware_name =
        firmware_for(device.id.device).ok_or(narf_bus::ProbeError::NotForThisDriver)?;

    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // Map BAR0: IPU6 register window.
    // SAFETY: exclusive BAR ownership held by bus probe contract.
    let regs =
        unsafe { map_bar(&device, BAR_REGS) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let ipu6 = Ipu6 {
        vid: device.id.vendor,
        did: device.id.device,
        variant,
        firmware_name,
        regs,
        queue: BufferQueue::new(),
    };

    *CONTROLLER.lock() = Some(ipu6);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-ipu6"),
        kind: narf_drivers::BoundKind::Media,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Media.default_domain(),
    });

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  intel-ipu6: probed (0x{:04X}:0x{:04X}, variant {:?}), firmware={}",
            device.id.vendor,
            device.id.device,
            variant,
            firmware_name,
        );
    }

    Ok(())
}

/// Register one PCI match entry per known IPU6 device ID.
pub fn register_pci_driver() {
    // Register a separate exact-match entry for each known DID so the
    // bus framework can log each one individually in the probe trace.
    for &(vendor, device) in PCI_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "intel-ipu6",
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}
