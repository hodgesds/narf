//! Intel NPU (VPU) — identification and buttress telemetry.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/accel/ivpu/` (GPL-2.0; NARF is
//! GPL-2.0-or-later so adaptation is permitted):
//!
//! - `ivpu_drv.h`               — PCI device IDs, `ivpu_hw_ip_gen`,
//!   `ivpu_hw_btrs_gen`, the `IVPU_PLATFORM_*` values.
//! - `ivpu_drv.c`               — `ivpu_pci_ids[]`, `ivpu_pci_init`
//!   (BAR0 = RegV, BAR4 = RegB).
//! - `ivpu_hw_btrs_lnl_reg.h`   — the buttress register offsets and
//!   field masks used below.
//! - `ivpu_hw_btrs.c`           — `read_tile_config_fuse`,
//!   `ivpu_hw_btrs_is_idle`, `pll_config_get_lnl`,
//!   `pll_ratio_to_mhz_lnl`.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** carries the NPU at PCI `00:0b.0`
//! (`8086:b03e`, "Panther Lake NPU"), which Linux calls
//! `PCI_DEVICE_ID_PTL_P` and maps to IP generation 50xx on the
//! Lunar-Lake-style buttress.
//!
//! ## Two BARs, two register files
//!
//! The device presents two distinct register windows and the driver
//! must not confuse them:
//!
//! - **BAR0 — RegV.** The VPU's own register file, only meaningful
//!   once firmware is running.
//! - **BAR4 — RegB.** The *buttress*: the always-on block that gates
//!   power, reports the tile fuse configuration, and owns the PLL.
//!   Everything this module reads lives here.
//!
//! ## Scope, and why it stops where it does
//!
//! Identification and buttress telemetry only: IP generation, tile
//! fuse configuration, ready/idle state, platform kind, and the
//! current PLL frequency.
//!
//! Booting the NPU means loading a signed firmware image, standing up
//! its MMU context, and driving the IPC and job queues. Linux cannot
//! do it without the blob either — on this very machine it reports
//! `ivpu_fw_request(): Failed to request firmware: -2` and gives up.
//! A driver that claimed to bring up the NPU while having nothing to
//! load onto it would be claiming something it cannot do, so this one
//! does not: it reports what the buttress says and registers no
//! [`crate::AccelDeviceTrait`].

extern crate alloc;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `ivpu_pci_ids[]`.

/// Intel.
pub const NPU_VENDOR: u16 = 0x8086;

/// Meteor Lake — `PCI_DEVICE_ID_MTL`.
pub const NPU_DEV_MTL: u16 = 0x7D1D;
/// Arrow Lake — `PCI_DEVICE_ID_ARL`.
pub const NPU_DEV_ARL: u16 = 0xAD1D;
/// Lunar Lake — `PCI_DEVICE_ID_LNL`.
pub const NPU_DEV_LNL: u16 = 0x643E;
/// Panther Lake-P — `PCI_DEVICE_ID_PTL_P`. The MS-03's `00:0b.0`.
pub const NPU_DEV_PTL_P: u16 = 0xB03E;
/// Wildcat Lake — `PCI_DEVICE_ID_WCL`.
pub const NPU_DEV_WCL: u16 = 0xFD3E;
/// Nova Lake — `PCI_DEVICE_ID_NVL`.
pub const NPU_DEV_NVL: u16 = 0xD71D;

/// Every device ID this driver claims, in one `const` so
/// `register_pci_driver` and the match-table smoke cannot drift.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    NPU_DEV_MTL,
    NPU_DEV_ARL,
    NPU_DEV_LNL,
    NPU_DEV_PTL_P,
    NPU_DEV_WCL,
    NPU_DEV_NVL,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

// ── Generations ─────────────────────────────────────────────────────

/// NPU IP generation — `ivpu_hw_ip_gen`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpGen {
    /// `IVPU_HW_IP_37XX` — Meteor Lake, Arrow Lake.
    Ip37xx,
    /// `IVPU_HW_IP_40XX` — Lunar Lake.
    Ip40xx,
    /// `IVPU_HW_IP_50XX` — Panther Lake, Wildcat Lake.
    Ip50xx,
    /// `IVPU_HW_IP_60XX` — Nova Lake.
    Ip60xx,
    /// A device id outside the table.
    Unknown,
}

/// Buttress generation — `ivpu_hw_btrs_gen`. This is *not* the same
/// split as [`IpGen`]: Lunar Lake and Panther Lake share the LNL
/// buttress despite being different IP generations, so the register
/// map below is selected by this, not by `IpGen`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtrsGen {
    /// `IVPU_HW_BTRS_MTL`.
    Mtl,
    /// `IVPU_HW_BTRS_LNL`.
    Lnl,
    /// A device id outside the table.
    Unknown,
}

/// IP generation for a device id.
pub const fn ip_gen_for(did: u16) -> IpGen {
    match did {
        NPU_DEV_MTL | NPU_DEV_ARL => IpGen::Ip37xx,
        NPU_DEV_LNL => IpGen::Ip40xx,
        NPU_DEV_PTL_P | NPU_DEV_WCL => IpGen::Ip50xx,
        NPU_DEV_NVL => IpGen::Ip60xx,
        _ => IpGen::Unknown,
    }
}

/// Buttress generation for a device id.
pub const fn btrs_gen_for(did: u16) -> BtrsGen {
    match did {
        NPU_DEV_MTL | NPU_DEV_ARL => BtrsGen::Mtl,
        NPU_DEV_LNL | NPU_DEV_PTL_P | NPU_DEV_WCL | NPU_DEV_NVL => BtrsGen::Lnl,
        _ => BtrsGen::Unknown,
    }
}

// ── BARs ────────────────────────────────────────────────────────────

/// BAR0 — `RegV`, the VPU's own register file.
pub const NPU_BAR_REGV: u8 = 0;
/// BAR4 — `RegB`, the buttress register file.
pub const NPU_BAR_REGB: u8 = 4;

// ── Buttress registers (BAR4, LNL layout) ───────────────────────────
//
// `ivpu_hw_btrs_lnl_reg.h`.

/// `VPU_HW_BTRS_LNL_INTERRUPT_STAT`.
pub const BTRS_INTERRUPT_STAT: u64 = 0x0000;
/// Frequency-change interrupt.
pub const BTRS_INT_FREQ_CHANGE: u32 = 1 << 0;
/// ATS error.
pub const BTRS_INT_ATS_ERR: u32 = 1 << 1;
/// CFI0 error.
pub const BTRS_INT_CFI0_ERR: u32 = 1 << 2;
/// CFI1 error.
pub const BTRS_INT_CFI1_ERR: u32 = 1 << 3;
/// IMR0 error.
pub const BTRS_INT_IMR0_ERR: u32 = 1 << 4;
/// IMR1 error.
pub const BTRS_INT_IMR1_ERR: u32 = 1 << 5;
/// Survivability error.
pub const BTRS_INT_SURV_ERR: u32 = 1 << 6;

/// `VPU_HW_BTRS_LNL_PLL_FREQ`.
pub const BTRS_PLL_FREQ: u64 = 0x0148;
/// `PLL_FREQ_RATIO_MASK` — bits 15:0.
pub const BTRS_PLL_FREQ_RATIO_MASK: u32 = 0xFFFF;

/// `VPU_HW_BTRS_LNL_TILE_FUSE`.
pub const BTRS_TILE_FUSE: u64 = 0x0150;
/// `TILE_FUSE_VALID_MASK` — bit 0. Clear means the fuse read is not
/// trustworthy and the config field below is meaningless.
pub const BTRS_TILE_FUSE_VALID: u32 = 1 << 0;
/// `TILE_FUSE_CONFIG_MASK` — bits 6:1. A *disable* mask: a set bit
/// means that tile is fused off.
pub const BTRS_TILE_FUSE_CONFIG_SHIFT: u32 = 1;
/// Width of the tile-disable field, after shifting down.
pub const BTRS_TILE_FUSE_CONFIG_MASK: u32 = 0x3F;

/// `VPU_HW_BTRS_LNL_VPU_STATUS`.
pub const BTRS_VPU_STATUS: u64 = 0x0154;
/// `VPU_STATUS_READY_MASK`.
pub const BTRS_STATUS_READY: u32 = 1 << 0;
/// `VPU_STATUS_IDLE_MASK`.
pub const BTRS_STATUS_IDLE: u32 = 1 << 1;
/// `VPU_STATUS_DUP_IDLE_MASK`.
pub const BTRS_STATUS_DUP_IDLE: u32 = 1 << 2;
/// `VPU_STATUS_CLOCK_RESOURCE_OWN_ACK_MASK`.
pub const BTRS_STATUS_CLOCK_RES_OWN_ACK: u32 = 1 << 6;
/// `VPU_STATUS_POWER_RESOURCE_OWN_ACK_MASK`.
pub const BTRS_STATUS_POWER_RES_OWN_ACK: u32 = 1 << 7;
/// `VPU_STATUS_PERF_CLK_MASK`.
pub const BTRS_STATUS_PERF_CLK: u32 = 1 << 11;
/// `VPU_STATUS_PLATFORM_MASK` — bits 31:29.
pub const BTRS_STATUS_PLATFORM_SHIFT: u32 = 29;
/// Width of the platform field, after shifting down.
pub const BTRS_STATUS_PLATFORM_MASK: u32 = 0x7;

/// Highest buttress offset this driver reads.
const HIGHEST_BTRS_OFFSET: u64 = BTRS_VPU_STATUS;

/// `PLL_REF_CLK_FREQ_MHZ`.
pub const PLL_REF_CLK_FREQ_MHZ: u32 = 50;

/// Convert a PLL ratio to MHz.
///
/// The two buttress generations scale differently —
/// `pll_ratio_to_mhz_mtl` is `ratio * 50 * 2 / 3` while
/// `pll_ratio_to_mhz_lnl` is `ratio * 50 / 2`. Using the wrong one
/// reports a frequency that is off by a third.
pub const fn pll_ratio_to_mhz(gen: BtrsGen, ratio: u32) -> u32 {
    match gen {
        BtrsGen::Mtl => (ratio * PLL_REF_CLK_FREQ_MHZ * 2) / 3,
        BtrsGen::Lnl => (ratio * PLL_REF_CLK_FREQ_MHZ) / 2,
        BtrsGen::Unknown => 0,
    }
}

// ── Platform ────────────────────────────────────────────────────────

/// What the `VPU_STATUS` platform field reports the device is —
/// `IVPU_PLATFORM_*`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Real silicon.
    Silicon,
    /// Simics model.
    Simics,
    /// FPGA emulation.
    Fpga,
    /// HSLE emulation.
    Hsle,
    /// A value outside the documented set.
    Invalid(u8),
}

impl Platform {
    /// Decode the 3-bit platform field.
    pub const fn from_field(v: u8) -> Self {
        match v {
            0 => Platform::Silicon,
            2 => Platform::Simics,
            3 => Platform::Fpga,
            4 => Platform::Hsle,
            other => Platform::Invalid(other),
        }
    }

    /// Short label for the boot transcript.
    pub const fn label(self) -> &'static str {
        match self {
            Platform::Silicon => "silicon",
            Platform::Simics => "simics",
            Platform::Fpga => "fpga",
            Platform::Hsle => "hsle",
            Platform::Invalid(_) => "invalid",
        }
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NpuError {
    /// BAR0 (RegV) would not map.
    RegvMapFailed,
    /// BAR4 (RegB) would not map.
    RegbMapFailed,
    /// BAR4 does not cover the buttress register block.
    RegbTooSmall,
    /// Registers read back all-ones — the device is not responding.
    DeviceGone,
    /// This driver has no buttress register map for the device's
    /// generation.
    UnsupportedGeneration,
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed NPU, identified from its buttress.
pub struct IntelNpu {
    /// BAR0 — the VPU register file. Mapped so a future firmware path
    /// does not have to re-derive it, but not read here.
    regv: MmioRegion,
    /// BAR4 — the buttress register file.
    regb: MmioRegion,
    /// PCI device id.
    pub device_id: u16,
    /// NPU IP generation.
    pub ip_gen: IpGen,
    /// Buttress generation, which selects the register map.
    pub btrs_gen: BtrsGen,
    /// `VPU_STATUS` as read at probe.
    pub status: u32,
    /// `TILE_FUSE` as read at probe.
    pub tile_fuse: u32,
}

// SAFETY: `IntelNpu` has no interior mutability; both MMIO regions
// describe identity-mapped windows this driver owns exclusively and
// the remaining fields are plain data written once at bring-up.
unsafe impl Send for IntelNpu {}
// SAFETY: every accessor is a read of an independent buttress
// register, so concurrent `&IntelNpu` use from several CPUs is sound.
unsafe impl Sync for IntelNpu {}

impl core::fmt::Debug for IntelNpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelNpu")
            .field("device_id", &self.device_id)
            .field("ip_gen", &self.ip_gen)
            .field("btrs_gen", &self.btrs_gen)
            .field("status", &self.status)
            .field("tile_fuse", &self.tile_fuse)
            .finish_non_exhaustive()
    }
}

impl IntelNpu {
    /// Map both BARs and read the buttress identity registers.
    ///
    /// # Safety
    /// Caller owns the device's BARs exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NpuError> {
        let btrs_gen = btrs_gen_for(device.id.device);
        if btrs_gen != BtrsGen::Lnl {
            // Only the LNL buttress map is transcribed here. Meteor
            // Lake's differs, and guessing at it would be worse than
            // declining the device.
            return Err(NpuError::UnsupportedGeneration);
        }

        // SAFETY: forwarded — caller owns the BARs.
        let regv = unsafe { map_bar(device, NPU_BAR_REGV) }.map_err(|_| NpuError::RegvMapFailed)?;
        // SAFETY: same.
        let regb = unsafe { map_bar(device, NPU_BAR_REGB) }.map_err(|_| NpuError::RegbMapFailed)?;
        if regb.len < HIGHEST_BTRS_OFFSET + 4 {
            return Err(NpuError::RegbTooSmall);
        }

        // SAFETY: `regb` is the mapped buttress window and both
        // offsets are in range per the check above.
        let (status, tile_fuse) =
            unsafe { (regb.read32(BTRS_VPU_STATUS), regb.read32(BTRS_TILE_FUSE)) };
        if status == 0xFFFF_FFFF {
            return Err(NpuError::DeviceGone);
        }

        Ok(Self {
            regv,
            regb,
            device_id: device.id.device,
            ip_gen: ip_gen_for(device.id.device),
            btrs_gen,
            status,
            tile_fuse,
        })
    }

    /// `ivpu_hw_btrs_is_idle` — ready *and* idle. Either bit alone is
    /// not enough.
    pub const fn is_idle(&self) -> bool {
        self.status & BTRS_STATUS_READY != 0 && self.status & BTRS_STATUS_IDLE != 0
    }

    /// `VPU_STATUS.READY`.
    pub const fn is_ready(&self) -> bool {
        self.status & BTRS_STATUS_READY != 0
    }

    /// What the buttress says it is running on.
    pub const fn platform(&self) -> Platform {
        Platform::from_field(
            ((self.status >> BTRS_STATUS_PLATFORM_SHIFT) & BTRS_STATUS_PLATFORM_MASK) as u8,
        )
    }

    /// `TILE_FUSE.VALID`.
    pub const fn tile_fuse_valid(&self) -> bool {
        self.tile_fuse & BTRS_TILE_FUSE_VALID != 0
    }

    /// The tile *disable* mask — a set bit means that tile is fused
    /// off. Returns `None` when the fuse read is not valid.
    pub const fn tile_disable_mask(&self) -> Option<u32> {
        if !self.tile_fuse_valid() {
            return None;
        }
        Some((self.tile_fuse >> BTRS_TILE_FUSE_CONFIG_SHIFT) & BTRS_TILE_FUSE_CONFIG_MASK)
    }

    /// Number of tiles fused off, or `None` when the fuse is invalid.
    /// Linux warns when more than one tile is disabled.
    pub const fn disabled_tile_count(&self) -> Option<u32> {
        match self.tile_disable_mask() {
            Some(m) => Some(m.count_ones()),
            None => None,
        }
    }

    /// Current PLL ratio, straight from `PLL_FREQ`.
    pub fn pll_ratio(&self) -> u32 {
        // SAFETY: `self.regb` is the mapped buttress window and
        // `BTRS_PLL_FREQ` is below `HIGHEST_BTRS_OFFSET`.
        let v = unsafe { self.regb.read32(BTRS_PLL_FREQ) };
        v & BTRS_PLL_FREQ_RATIO_MASK
    }

    /// Current NPU clock in MHz.
    pub fn pll_freq_mhz(&self) -> u32 {
        pll_ratio_to_mhz(self.btrs_gen, self.pll_ratio())
    }

    /// Pending buttress interrupt causes.
    pub fn interrupt_status(&self) -> u32 {
        // SAFETY: as above; `BTRS_INTERRUPT_STAT` is offset 0.
        unsafe { self.regb.read32(BTRS_INTERRUPT_STAT) }
    }

    /// Re-read `VPU_STATUS`.
    pub fn refresh_status(&mut self) -> u32 {
        // SAFETY: as above.
        let s = unsafe { self.regb.read32(BTRS_VPU_STATUS) };
        self.status = s;
        s
    }

    /// Physical base of BAR0 (RegV), for diagnostics.
    pub fn regv_base(&self) -> u64 {
        self.regv.phys.raw()
    }

    /// Physical base of BAR4 (RegB), for diagnostics.
    pub fn regb_base(&self) -> u64 {
        self.regb.phys.raw()
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<alloc::sync::Arc<IntelNpu>>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != NPU_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let dev = match unsafe { IntelNpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  intel-npu: bring-up failed on {:04x}: {:?}",
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
            "  intel-npu: {:04x} {:?}/{:?} {} {} {} MHz, tiles-off={}, RegV={:#018x} RegB={:#018x}",
            dev.device_id,
            dev.ip_gen,
            dev.btrs_gen,
            dev.platform().label(),
            if dev.is_idle() {
                "ready+idle"
            } else if dev.is_ready() {
                "ready"
            } else {
                "not-ready"
            },
            dev.pll_freq_mhz(),
            match dev.disabled_tile_count() {
                Some(n) => n as i32,
                None => -1,
            },
            dev.regv_base(),
            dev.regb_base(),
        );
        let _ = writeln!(
            narf_console::Writer,
            "  intel-npu: no firmware path in tree; NPU left unbooted"
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-npu"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    *CONTROLLER.lock() = Some(alloc::sync::Arc::new(dev));
    Ok(())
}

/// Register the NPU PCI driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "intel-npu",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: NPU_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once an NPU has been probed.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed NPU, if any.
pub fn with_device<R>(f: impl FnOnce(&IntelNpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: forget the probed device so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
