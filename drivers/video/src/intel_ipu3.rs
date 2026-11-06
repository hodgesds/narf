//! Intel IPU3 (Pixel Visual Core) — explicit refusal marker (#811).
//!
//! The IPU3 CSS pipeline bring-up is NOT implemented: there is no
//! CSS pipeline programming, no IMGU DMA pool, and no IRQ arming.
//! Probe therefore declines the IPU3 device with
//! `ProbeError::NotForThisDriver` *before touching the hardware* (no
//! PCI command enable, no BAR0 map, no bound-driver record, no video
//! node), so the device is never presented as bound and stays
//! available to the next claimant in the bus arbitration walk
//! (bus spec §9.3). This replaces the earlier probe-shaped stub,
//! which mapped BAR0, recorded a bound driver, and logged "probed"
//! for a camera that could never stream.
//!
//! Per-platform scoping lives in [`refusal_reason`]. The CSS
//! micro-firmware is embedded in the driver (there is no separate
//! blob to load), so the missing piece here is the pipeline itself,
//! not a firmware loader — unlike IPU6/MP2. Full CSS bring-up is
//! out of scope here; it needs Daniel's hardware confirmation (#811).
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
//! ## Deferred (Stage-2, needs hardware confirmation)
//!
//! CSS pipeline programming, ISP register writes, and DMA rings.
//! Until then probe refuses (see above) and the [`Camera`] methods
//! below are unreachable — no instance can exist without a
//! successful probe.

use narf_driver_runtime::{BusDevice, BusDeviceCap, Cap, Write};

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

// ── Refusal reason (per-platform scoping, #811) ───────────────────

/// Why probe refuses the IPU3 device ID.
///
/// Returns `None` for any other device ID. Unlike IPU6/MP2 there
/// is no firmware blob to name: the CSS micro-firmware is embedded
/// in the driver, and the missing piece is the CSS pipeline and
/// IMGU DMA pool to run it through.
pub fn refusal_reason(did: u16) -> Option<&'static str> {
    if did != IPU3_DID {
        return None;
    }
    Some(
        "intel-ipu3 (Skylake Y/U): CSS pipeline programming and the \
         IMGU DMA pool are not implemented, so the embedded CSS \
         micro-firmware has no pipeline to run through (#811)",
    )
}

// ── Firmware ────────────────────────────────────────────────────────

/// IPU3 embeds its CSS micro-firmware inside the driver binary itself
/// (via the `ipu3-css-fw.c` table). There is no separate blob to
/// request from the firmware registry.
pub const FIRMWARE_NAME: Option<&str> = None;

// ── Driver state ────────────────────────────────────────────────────

/// Probed IPU3 instance.
///
/// Unreachable while [`probe`] refuses: no instance can exist
/// without a successful probe. Kept as the Stage-2 skeleton.
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
        // Unreachable while probe refuses (#811): no instance can
        // exist without the CSS pipeline and IMGU DMA pool.
        // Stage-2 programs the format via `ipu3_css_set_parameters`.
        Err(CameraError::NotImplemented)
    }

    fn start_streaming(&self) -> Result<()> {
        // Unreachable while probe refuses (#811). Stage-2 arms the
        // IMGU CSS input-system and enables IRQs.
        Err(CameraError::NotImplemented)
    }

    fn stop_streaming(&self) -> Result<()> {
        // Unreachable while probe refuses (#811).
        Err(CameraError::NotImplemented)
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static CONTROLLER: narf_lib::sync::IrqSafeSpinLock<Option<Ipu3>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return `true` if an IPU3 was successfully probed at boot.
///
/// Always `false` while probe refuses (#811); kept as the
/// observable "never bound" predicate for tests and for Stage-2.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// PCI probe entry-point — explicit refusal (#811).
///
/// Declines the IPU3 device with `ProbeError::NotForThisDriver`
/// *before touching the hardware*: no PCI command enable, no BAR0
/// map, no singleton install, no bound-driver record. The bus
/// dispatcher returns the device to the candidate list so another
/// driver may claim it (bus spec §9.3). The per-platform reason is
/// logged so the refusal is visible on boot instead of silent;
/// unknown IDs decline silently as before.
///
/// # Safety
///
/// Caller must hold exclusive BAR access for the duration of probe
/// (enforced by the bus framework's ownership model). No BAR is
/// touched while refusing, so this is vacuous today; Stage-2
/// re-enables the mapping and the contract applies again.
pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> core::result::Result<(), narf_bus::ProbeError> {
    if device.id.vendor != INTEL_VENDOR || device.id.device != IPU3_DID {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let reason = refusal_reason(device.id.device).ok_or(narf_bus::ProbeError::NotForThisDriver)?;

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  intel-ipu3: refusing 0x{:04X}:0x{:04X} — {}",
            device.id.vendor,
            device.id.device,
            reason,
        );
    }

    Err(narf_bus::ProbeError::NotForThisDriver)
}

/// Register the IPU3 driver with the PCI bus.
///
/// The match stays registered so the bus framework routes the IPU3
/// device to [`probe`], which declines it honestly with the
/// per-platform reason — removing the match would leave the device
/// silently unclaimed with no trace of the refusal.
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
