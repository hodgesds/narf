//! Intel PCH SPI flash controller — the hardware-sequencing
//! interface to the BIOS flash.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 (GPL-2.0; NARF is GPL-2.0-or-later so adaptation
//! is permitted):
//!
//! - `drivers/spi/spi-intel.c`     — the register map (`BFPREG`,
//!   `HSFSTS_CTL`, `FRACC`, `FREG(n)`, `PR(n)`), the per-generation
//!   `CNL_PR` / `CNL_FREG_NUM` / `CNL_PR_NUM` constants, and the
//!   region / protected-range decode in `intel_spi_dump_regs`.
//! - `drivers/spi/spi-intel-pci.c` — the PCI id table and the
//!   `BCR.BIOSWE` write-enable bit at config offset 0xDC.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** exposes the controller at PCI `00:1f.5`
//! (`8086:e323`), which Linux's table maps to `cnl_info`.
//!
//! ## This driver is deliberately read-only
//!
//! The device it fronts is the flash chip the machine boots from.
//! Linux gates writes behind `intel_spi_pci_set_writeable`, which
//! sets `BCR.BIOSWE`, and even then most platforms have the
//! descriptor locked. Nothing in NARF has a reason to write BIOS
//! flash from a probe path, so this module exposes **no** write,
//! erase, or write-enable path at all — not a disabled one, an
//! absent one. What it does provide is the layout and lock state:
//! which regions exist, where they live, whether the descriptor is
//! valid, whether `FLOCKDN` is set, and which protected ranges are
//! armed. That is the part a boot transcript and a firmware-integrity
//! check actually want.
//!
//! ## Region addressing
//!
//! `FREG(n)` and `PR(n)` store base and limit in units of 4 KiB, in
//! 15-bit fields: base in bits 14:0, limit in bits 30:16. The limit
//! is **inclusive**, so a region's byte length is
//! `(limit - base + 1) * 4096`, and a region with `limit < base` is
//! *disabled*, not empty — see [`FlashRegion::is_valid`]. Reading the
//! limit as exclusive, or as an absolute byte address, are the two
//! ways this decode goes quietly wrong.

extern crate alloc;

use alloc::vec::Vec;

use narf_bus::{map_bar, BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `intel_spi_pci_ids[]`. Only the `cnl_info` (Cannon Lake and
// later) entries are claimed — that is the generation whose register
// layout the constants below describe.

/// Intel.
pub const SPI_VENDOR: u16 = 0x8086;

/// Comet Lake-LP.
pub const SPI_DEV_CML_LP: u16 = 0x02A4;
/// Comet Lake-H.
pub const SPI_DEV_CML_H: u16 = 0x06A4;
/// Cannon Lake-LP.
pub const SPI_DEV_CNL_LP: u16 = 0x9DA4;
/// Cannon Lake-H.
pub const SPI_DEV_CNL_H: u16 = 0xA324;
/// Tiger Lake-LP.
pub const SPI_DEV_TGL_LP: u16 = 0xA0A4;
/// Tiger Lake-H.
pub const SPI_DEV_TGL_H: u16 = 0x43A4;
/// Alder Lake-S.
pub const SPI_DEV_ADL_S: u16 = 0x7AA4;
/// Alder Lake-P.
pub const SPI_DEV_ADL_P: u16 = 0x51A4;
/// Alder Lake-M.
pub const SPI_DEV_ADL_M: u16 = 0x54A4;
/// Meteor Lake-P.
pub const SPI_DEV_MTL_P: u16 = 0x7E23;
/// Panther Lake-H — the MS-03's `00:1f.5`.
pub const SPI_DEV_PTL_H: u16 = 0xE323;
/// Panther Lake-P.
pub const SPI_DEV_PTL_P: u16 = 0xE423;

/// Every device ID this driver claims.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    SPI_DEV_CML_LP,
    SPI_DEV_CML_H,
    SPI_DEV_CNL_LP,
    SPI_DEV_CNL_H,
    SPI_DEV_TGL_LP,
    SPI_DEV_TGL_H,
    SPI_DEV_ADL_S,
    SPI_DEV_ADL_P,
    SPI_DEV_ADL_M,
    SPI_DEV_MTL_P,
    SPI_DEV_PTL_H,
    SPI_DEV_PTL_P,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

// ── Register offsets (BAR0) ─────────────────────────────────────────

/// The controller's register window is BAR0.
pub const SPI_BAR: u8 = 0;

/// `BFPREG` — BIOS Flash Primary Region. Same base/limit encoding as
/// an `FREG`.
pub const REG_BFPREG: u64 = 0x00;
/// `HSFSTS_CTL` — Hardware Sequencing Flash Status and Control.
pub const REG_HSFSTS_CTL: u64 = 0x04;
/// `FADDR` — flash linear address for the next hardware-sequenced
/// cycle.
pub const REG_FADDR: u64 = 0x08;
/// `DLOCK` — discrete lock bits.
pub const REG_DLOCK: u64 = 0x0C;
/// `FRACC` — Flash Region Access Permissions.
pub const REG_FRACC: u64 = 0x50;
/// `LVSCC` — host lower vendor-specific component capabilities.
pub const REG_LVSCC: u64 = 0xC4;
/// `UVSCC` — host upper vendor-specific component capabilities.
pub const REG_UVSCC: u64 = 0xC8;

/// `FDATA(n)` — flash data FIFO word `n`.
pub const fn reg_fdata(n: u32) -> u64 {
    0x10 + (n as u64) * 4
}
/// `FREG(n)` — flash region `n` base/limit.
pub const fn reg_freg(n: u32) -> u64 {
    0x54 + (n as u64) * 4
}
/// `CNL_PR + PR(n)` — protected range `n`. The `PR` block moved to
/// 0x84 on Cannon Lake and later.
pub const fn reg_pr(n: u32) -> u64 {
    CNL_PR_BASE + (n as u64) * 4
}

/// `CNL_PR` — base of the protected-range block.
pub const CNL_PR_BASE: u64 = 0x84;
/// `CNL_FREG_NUM` — number of flash regions on this generation.
pub const CNL_FREG_NUM: u32 = 6;
/// `CNL_PR_NUM` — number of protected-range registers.
pub const CNL_PR_NUM: u32 = 5;

// HSFSTS_CTL bits.
/// `HSFSTS_CTL_FSMIE` — flash SPI SMI enable.
pub const HSFSTS_CTL_FSMIE: u32 = 1 << 31;
/// `HSFSTS_CTL_FGO` — start a hardware-sequenced cycle.
pub const HSFSTS_CTL_FGO: u32 = 1 << 16;
/// `HSFSTS_CTL_FLOCKDN` — flash configuration lockdown. Once set,
/// the region and protected-range registers are read-only until the
/// next platform reset.
pub const HSFSTS_CTL_FLOCKDN: u32 = 1 << 15;
/// `HSFSTS_CTL_FDV` — flash descriptor valid. Clear means the part
/// is in descriptor-override mode and the region table below is
/// meaningless.
pub const HSFSTS_CTL_FDV: u32 = 1 << 14;
/// `HSFSTS_CTL_SCIP` — SPI cycle in progress.
pub const HSFSTS_CTL_SCIP: u32 = 1 << 5;
/// `HSFSTS_CTL_AEL` — access error log.
pub const HSFSTS_CTL_AEL: u32 = 1 << 2;
/// `HSFSTS_CTL_FCERR` — flash cycle error.
pub const HSFSTS_CTL_FCERR: u32 = 1 << 1;
/// `HSFSTS_CTL_FDONE` — flash cycle done.
pub const HSFSTS_CTL_FDONE: u32 = 1 << 0;

// FREG / PR field layout.
/// `FREG_BASE_MASK` / `PR_BASE_MASK` — bits 14:0.
pub const REGION_BASE_MASK: u32 = 0x7FFF;
/// `FREG_LIMIT_SHIFT` / `PR_LIMIT_SHIFT`.
pub const REGION_LIMIT_SHIFT: u32 = 16;
/// `FREG_LIMIT_MASK` / `PR_LIMIT_MASK`, after shifting down.
pub const REGION_LIMIT_MASK: u32 = 0x7FFF;
/// Base and limit are both in 4 KiB units.
pub const REGION_UNIT_BYTES: u64 = 4096;

/// `PR_WPE` — write protection enable for this protected range.
pub const PR_WPE: u32 = 1 << 31;
/// `PR_RPE` — read protection enable for this protected range.
pub const PR_RPE: u32 = 1 << 15;

/// Highest register offset this driver reads.
const HIGHEST_OFFSET: u64 = 0xC8;

// ── Region decode ───────────────────────────────────────────────────

/// One decoded `FREG(n)` — a flash descriptor region.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FlashRegion {
    /// Raw register value.
    pub raw: u32,
    /// Base, in 4 KiB units.
    pub base_blocks: u32,
    /// Limit, in 4 KiB units. **Inclusive.**
    pub limit_blocks: u32,
}

impl FlashRegion {
    /// Decode an `FREG` / `PR` / `BFPREG` value.
    pub const fn decode(raw: u32) -> Self {
        Self {
            raw,
            base_blocks: raw & REGION_BASE_MASK,
            limit_blocks: (raw >> REGION_LIMIT_SHIFT) & REGION_LIMIT_MASK,
        }
    }

    /// `true` if this region is present.
    ///
    /// A region the descriptor does not define reads back with the
    /// limit below the base (canonically base = 0x7FFF, limit = 0).
    /// That is the "disabled" encoding, not a zero-length region.
    pub const fn is_valid(&self) -> bool {
        self.limit_blocks >= self.base_blocks
    }

    /// First byte of the region.
    pub const fn base_bytes(&self) -> u64 {
        self.base_blocks as u64 * REGION_UNIT_BYTES
    }

    /// Length in bytes, or 0 when the region is disabled. The limit
    /// is inclusive, hence the `+ 1`.
    pub const fn len_bytes(&self) -> u64 {
        if !self.is_valid() {
            return 0;
        }
        (self.limit_blocks as u64 - self.base_blocks as u64 + 1) * REGION_UNIT_BYTES
    }

    /// One past the last byte of the region, or 0 when disabled.
    pub const fn end_bytes(&self) -> u64 {
        if !self.is_valid() {
            return 0;
        }
        self.base_bytes() + self.len_bytes()
    }
}

/// One decoded `PR(n)` — a protected range.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtectedRange {
    /// Address range covered.
    pub region: FlashRegion,
    /// `PR_WPE` — writes to the range are blocked.
    pub write_protected: bool,
    /// `PR_RPE` — reads from the range are blocked.
    pub read_protected: bool,
}

impl ProtectedRange {
    /// Decode a `PR(n)` value.
    pub const fn decode(raw: u32) -> Self {
        Self {
            region: FlashRegion::decode(raw),
            write_protected: raw & PR_WPE != 0,
            read_protected: raw & PR_RPE != 0,
        }
    }

    /// `true` when this protected range actually protects something.
    /// A range with neither enable bit set is inert even if its
    /// base/limit look sane.
    pub const fn is_armed(&self) -> bool {
        (self.write_protected || self.read_protected) && self.region.is_valid()
    }
}

/// Conventional meaning of each flash descriptor region index.
pub const fn region_name(index: u32) -> &'static str {
    match index {
        0 => "descriptor",
        1 => "bios",
        2 => "me",
        3 => "gbe",
        4 => "platform-data",
        5 => "device-expansion",
        _ => "region",
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpiFlashError {
    BarMapFailed,
    /// BAR0 does not cover the register block.
    BarTooSmall,
    /// Registers read back all-ones — the device is not responding.
    DeviceGone,
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed PCH SPI flash controller.
#[derive(Debug)]
pub struct IntelSpiFlash {
    /// PCI device id.
    pub device_id: u16,
    /// `HSFSTS_CTL` as read at probe.
    pub hsfsts_ctl: u32,
    /// `BFPREG` — the BIOS region the host boots from.
    pub bios_region: FlashRegion,
    /// `FRACC` — per-region read / write access permissions.
    pub fracc: u32,
    /// Decoded `FREG(0..CNL_FREG_NUM)`.
    pub regions: Vec<FlashRegion>,
    /// Decoded `PR(0..CNL_PR_NUM)`.
    pub protected_ranges: Vec<ProtectedRange>,
}

impl IntelSpiFlash {
    /// `HSFSTS_CTL_FDV` — the flash descriptor is valid, so
    /// [`Self::regions`] means something.
    pub const fn descriptor_valid(&self) -> bool {
        self.hsfsts_ctl & HSFSTS_CTL_FDV != 0
    }

    /// `HSFSTS_CTL_FLOCKDN` — the flash configuration is locked until
    /// the next platform reset.
    pub const fn locked_down(&self) -> bool {
        self.hsfsts_ctl & HSFSTS_CTL_FLOCKDN != 0
    }

    /// Total flash size implied by the descriptor: one past the end
    /// of the highest valid region.
    pub fn flash_size_bytes(&self) -> u64 {
        self.regions
            .iter()
            .filter(|r| r.is_valid())
            .map(|r| r.end_bytes())
            .max()
            .unwrap_or(0)
    }

    /// Protected ranges that are actually armed.
    pub fn armed_protected_ranges(&self) -> impl Iterator<Item = &ProtectedRange> {
        self.protected_ranges.iter().filter(|p| p.is_armed())
    }

    /// Map BAR0 and read the flash layout.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, SpiFlashError> {
        // SAFETY: forwarded — caller owns BAR0.
        let mmio = unsafe { map_bar(device, SPI_BAR) }.map_err(|_| SpiFlashError::BarMapFailed)?;
        if mmio.len < HIGHEST_OFFSET + 4 {
            return Err(SpiFlashError::BarTooSmall);
        }
        // SAFETY: `mmio` is the mapped window; every offset read below
        // is at or under `HIGHEST_OFFSET`, checked above. All reads
        // here are of status/configuration registers with no side
        // effects — nothing starts a flash cycle.
        unsafe {
            let hsfsts_ctl = mmio.read32(REG_HSFSTS_CTL);
            if hsfsts_ctl == 0xFFFF_FFFF {
                return Err(SpiFlashError::DeviceGone);
            }
            let bios_region = FlashRegion::decode(mmio.read32(REG_BFPREG));
            let fracc = mmio.read32(REG_FRACC);

            let mut regions = Vec::with_capacity(CNL_FREG_NUM as usize);
            for n in 0..CNL_FREG_NUM {
                regions.push(FlashRegion::decode(mmio.read32(reg_freg(n))));
            }
            let mut protected_ranges = Vec::with_capacity(CNL_PR_NUM as usize);
            for n in 0..CNL_PR_NUM {
                protected_ranges.push(ProtectedRange::decode(mmio.read32(reg_pr(n))));
            }

            Ok(Self {
                device_id: device.id.device,
                hsfsts_ctl,
                bios_region,
                fracc,
                regions,
                protected_ranges,
            })
        }
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<alloc::sync::Arc<IntelSpiFlash>>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != SPI_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE only: this driver never issues a flash cycle, so it
    // has no use for bus mastering.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let dev = match unsafe { IntelSpiFlash::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  intel-spi: bring-up failed on {:04x}: {:?}",
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  intel-spi: {:04x} flash={} KiB descriptor={} lockdown={} bios={:#x}..{:#x} {} PR armed",
            dev.device_id,
            dev.flash_size_bytes() / 1024,
            if dev.descriptor_valid() { "valid" } else { "invalid" },
            if dev.locked_down() { "on" } else { "off" },
            dev.bios_region.base_bytes(),
            dev.bios_region.end_bytes(),
            dev.armed_protected_ranges().count(),
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-spi"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    *CONTROLLER.lock() = Some(alloc::sync::Arc::new(dev));
    Ok(())
}

/// Register the SPI flash controller driver — one match entry per
/// device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "intel-spi-flash",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: SPI_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once a controller has been probed.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed controller, if any.
pub fn with_controller<R>(f: impl FnOnce(&IntelSpiFlash) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: forget the probed controller so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
