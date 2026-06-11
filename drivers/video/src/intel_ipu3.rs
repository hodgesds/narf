//! Intel IPU3 (Pixel Visual Core) driver scaffold — Stage-0/1.
//!
//! ## Reference (Linux GPL, post 2026-05-20 relicense)
//!
//! - `linux/drivers/staging/media/ipu3/ipu3.c`:
//!   `IMGU_PCI_ID = 0x1919`, single-entry `imgu_pci_tbl`.
//! - `linux/drivers/staging/media/ipu3/ipu3.h`:
//!   BAR layout, IRQ, DMA-pool geometry.
//!
//! ## PCI identity
//!
//! | Vendor | Device | Platform             |
//! |--------|--------|----------------------|
//! | 0x8086 | 0x1919 | Skylake-Y / Skylake-U |
//!
//! ## Stage-1 scope
//!
//! 1. Claim the PCIe device (exact VID:DID match).
//! 2. Map BAR0 (IMGU register window).
//! 3. Resolve firmware name (IPU3 has no separate user-loaded FW;
//!    the CSS micro-firmware is embedded in the driver).
//! 4. Record a bound-driver entry so observability can enumerate it.
//!
//! No CSS pipeline programming, ISP register writes, or DMA rings
//! are attempted at this stage.

extern crate alloc;

use narf_driver_runtime::{map_bar, BusDevice, BusDeviceCap, Cap, Write};

use crate::{BufferQueue, Camera, CameraError, PixelFormat, Result};

// ── PCI IDs ─────────────────────────────────────────────────────────

/// Intel vendor ID.
pub const INTEL_VENDOR: u16 = 0x8086;

/// IPU3 Pixel Visual Core — Skylake-Y/U.
/// Source: `linux/drivers/staging/media/ipu3/ipu3.c`
/// `#define IMGU_PCI_ID 0x1919`.
pub const IPU3_DID: u16 = 0x1919;

/// PCI ID table entry for registration/testing.
pub const PCI_IDS: &[(u16, u16)] = &[(INTEL_VENDOR, IPU3_DID)];

/// BAR index for the IMGU register window.
/// Linux: `ipu3.c` references `pci_resource_start(pdev, 0)`.
const BAR_REGS: u8 = 0;

// ── Firmware ────────────────────────────────────────────────────────

/// IPU3 embeds its CSS micro-firmware inside the driver binary itself
/// (via the `ipu3-css-fw.c` table). There is no separate blob to
/// request from the firmware registry.
pub const FIRMWARE_NAME: Option<&str> = None;

// ── Driver state ────────────────────────────────────────────────────

/// Probed IPU3 instance.
#[derive(Debug)]
pub struct Ipu3 {
    /// Vendor ID from PCI config space (always `INTEL_VENDOR`).
    pub vid: u16,
    /// Device ID from PCI config space (always `IPU3_DID`).
    pub did: u16,
    /// MMIO region for the IMGU register window (BAR0).
    pub regs: narf_driver_runtime::MmioRegion,
    /// Buffer queue for camera capture frames.
    queue: BufferQueue,
}

impl Camera for Ipu3 {
    fn buffer_queue(&self) -> &BufferQueue {
        &self.queue
    }

    fn buffer_queue_mut(&mut self) -> &mut BufferQueue {
        &mut self.queue
    }

    fn set_format(&self, _fmt: PixelFormat, _w: u32, _h: u32) -> Result<()> {
        // Stage-2: program IPU3 CSS pipeline format. CSS micro-FW
        // must be loaded first; the `ipu3_css_set_parameters` path
        // requires a working IMGU DMA pool.
        Err(CameraError::NotImplemented)
    }

    fn start_streaming(&self) -> Result<()> {
        // Stage-2: arm the IMGU CSS input-system and enable IRQs.
        Err(CameraError::NotImplemented)
    }

    fn stop_streaming(&self) -> Result<()> {
        Err(CameraError::NotImplemented)
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static CONTROLLER: narf_lib::sync::IrqSafeSpinLock<Option<Ipu3>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return `true` if an IPU3 was successfully probed at boot.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// PCI probe entry-point.
///
/// # Safety
///
/// Caller must hold exclusive BAR access for the duration of probe
/// (enforced by the bus framework's ownership model).
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> core::result::Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    if device.id.vendor != INTEL_VENDOR || device.id.device != IPU3_DID {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    // Enable MMIO + bus-master.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // Map BAR0: IMGU register window.
    let regs =
        // SAFETY: exclusive BAR ownership held by the bus probe contract.
        unsafe { map_bar(&device, BAR_REGS) }.map_err(|_| narf_bus::ProbeError::BadDevice)?;

    let ipu3 = Ipu3 {
        vid: device.id.vendor,
        did: device.id.device,
        regs,
        queue: BufferQueue::new(),
    };

    *CONTROLLER.lock() = Some(ipu3);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-ipu3"),
        kind: narf_drivers::BoundKind::Media,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Media.default_domain(),
    });

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  intel-ipu3: probed (0x{:04X}:0x{:04X}), no user firmware blob required",
            device.id.vendor,
            device.id.device,
        );
    }

    Ok(())
}

/// Register the IPU3 driver with the PCI bus.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "intel-ipu3",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: INTEL_VENDOR,
            device: IPU3_DID,
        },
        probe,
    });
}
