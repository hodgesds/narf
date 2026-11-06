//! Intel IPU6 Image Signal Processor — explicit refusal marker (#811).
//!
//! The IPU6 firmware/CSI bring-up is NOT implemented: there is no CPD
//! image parser, no firmware load, no ISYS stream configuration, and
//! no DMA ring. Probe therefore declines every IPU6 device with
//! `ProbeError::NotForThisDriver` *before touching the hardware* (no
//! PCI command enable, no BAR0 map, no bound-driver record, no video
//! node), so the device is never presented as bound and stays
//! available to the next claimant in the bus arbitration walk
//! (bus spec §9.3). This replaces the earlier probe-shaped stub,
//! which mapped BAR0, recorded a bound driver, and logged "probed"
//! for a camera that could never stream.
//!
//! Per-platform scoping lives in [`refusal_reason`]: each variant
//! gets its own reason naming the platform and the firmware blob
//! that has no loader yet. Full firmware/CSI bring-up is out of
//! scope here — it needs Daniel's hardware confirmation (#811).
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
//! ## Deferred (Stage-2, needs hardware confirmation)
//!
//! Firmware loading requires the IPU6 Complex Peripheral Device (CPD)
//! image parser (`ipu6-cpd.c`); ISYS/CSI bring-up and the DMA ring
//! come after it. Until then probe refuses (see above) and the
//! [`Camera`] methods below are unreachable — no instance can exist
//! without a successful probe.

use narf_driver_runtime::{BusDevice, BusDeviceCap, Cap, Write};

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

// ── Refusal reason (per-platform scoping, #811) ───────────────────

/// Why probe refuses this IPU6 device ID, naming the platform and
/// the firmware blob that has no loader yet.
///
/// Returns `None` for unknown device IDs. The reason is the
/// per-platform scoping contract: the refusal for a Tiger Lake part
/// must name `ipu6_fw.bin`, not another variant's blob.
pub fn refusal_reason(did: u16) -> Option<&'static str> {
    match Ipu6Variant::from_did(did)? {
        Ipu6Variant::Ipu6 => Some(
            "intel-ipu6 (Tiger Lake, firmware intel/ipu/ipu6_fw.bin): \
             no CPD firmware loader and no ISYS/CSI bring-up yet (#811)",
        ),
        Ipu6Variant::Ipu6Se => Some(
            "intel-ipu6 (Jasper Lake SE, firmware intel/ipu/ipu6se_fw.bin): \
             no CPD firmware loader and no ISYS/CSI bring-up yet (#811)",
        ),
        Ipu6Variant::Ipu6Ep => Some(
            "intel-ipu6 (Alder Lake-P / Raptor Lake-P, firmware intel/ipu/ipu6ep_fw.bin): \
             no CPD firmware loader and no ISYS/CSI bring-up yet (#811)",
        ),
        Ipu6Variant::Ipu6EpAdln => Some(
            "intel-ipu6 (Alder Lake-N, firmware intel/ipu/ipu6epadln_fw.bin): \
             no CPD firmware loader and no ISYS/CSI bring-up yet (#811)",
        ),
        Ipu6Variant::Ipu6EpMtl => Some(
            "intel-ipu6 (Meteor Lake, firmware intel/ipu/ipu6epmtl_fw.bin): \
             no CPD firmware loader and no ISYS/CSI bring-up yet (#811)",
        ),
    }
}

// ── Driver state ─────────────────────────────────────────────────────

/// Probed IPU6 instance.
///
/// Unreachable while [`probe`] refuses: no instance can exist
/// without a successful probe. Kept as the Stage-2 skeleton — when
/// firmware/CSI bring-up lands, probe constructs this again.
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
        // Unreachable while probe refuses (#811): no instance can
        // exist without firmware loaded and ISYS streams configured.
        // Stage-2 programs the ISYS format via IPU6 firmware IPC.
        Err(CameraError::NotImplemented)
    }

    fn start_streaming(&self) -> Result<()> {
        // Unreachable while probe refuses (#811). Stage-2 sends
        // STREAM_START IPC to the IPU6 firmware.
        Err(CameraError::NotImplemented)
    }

    fn stop_streaming(&self) -> Result<()> {
        // Unreachable while probe refuses (#811).
        Err(CameraError::NotImplemented)
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static CONTROLLER: narf_lib::sync::IrqSafeSpinLock<Option<Ipu6>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return `true` if an IPU6 was successfully probed at boot.
///
/// Always `false` while probe refuses (#811); kept as the
/// observable "never bound" predicate for tests and for Stage-2,
/// when a successful probe will set it again.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Probe function for all IPU6 device IDs — explicit refusal (#811).
///
/// Declines every known IPU6 device with
/// `ProbeError::NotForThisDriver` *before touching the hardware*:
/// no PCI command enable, no BAR0 map, no singleton install, no
/// bound-driver record. The bus dispatcher returns the device to
/// the candidate list so another driver may claim it (bus spec
/// §9.3). The per-platform reason is logged so the refusal is
/// visible on boot instead of silent; unknown IDs decline silently
/// as before (they were never this driver's device).
///
/// # Safety
///
/// Exclusive BAR access must be held by the bus probe framework.
/// No BAR is touched while refusing, so this is vacuous today;
/// Stage-2 re-enables the mapping and the contract applies again.
pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> core::result::Result<(), narf_bus::ProbeError> {
    if device.id.vendor != INTEL_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let reason = refusal_reason(device.id.device).ok_or(narf_bus::ProbeError::NotForThisDriver)?;

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  intel-ipu6: refusing 0x{:04X}:0x{:04X} — {}",
            device.id.vendor,
            device.id.device,
            reason,
        );
    }

    Err(narf_bus::ProbeError::NotForThisDriver)
}

/// Register one PCI match entry per known IPU6 device ID.
///
/// The matches stay registered so the bus framework routes each
/// IPU6 device to [`probe`], which declines it honestly with the
/// per-platform reason — removing the matches would leave the
/// device silently unclaimed with no trace of the refusal.
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
