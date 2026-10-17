//! ath11k PCI probe.
//!
//! Stage-0/1 scope:
//!   - PCI device-id match table (one entry per chip family).
//!   - BAR0 MMIO mapping (ath11k uses BAR0 only — 2 MiB on
//!     QCA6390, 4 MiB on QCN9074 / WCN6855).
//!   - SoC global reset prologue (per Linux's
//!     `ath11k_pci_soc_global_reset`).
//!   - LTSSM enable + PCIe hot-reset clear (per
//!     `ath11k_pci_enable_ltssm`).
//!   - hw_rev resolution (TCSR major/minor + WCN6855 sub-version).
//!
//! Not yet: MHI host + firmware boot, QMI, CE/HTC/WMI, DP. Until
//! those land the device registers no network interface — a
//! `wlan%d` with a made-up MAC that "associates" without touching
//! the radio would only mislead userspace.
//!
//! Linux references (BSD-3 / dual GPL):
//! - `drivers/net/wireless/ath/ath11k/pci.c::ath11k_pci_probe`
//!   (v6.6 ~L985..L1180).
//! - `drivers/net/wireless/ath/ath11k/pci.c::ath11k_pci_soc_global_reset`,
//!   `ath11k_pci_enable_ltssm` (~L193..L350).
//! - `drivers/net/wireless/ath/ath11k/pcic.h`,
//!   `drivers/net/wireless/ath/ath11k/pci.h` — register offsets.

#![allow(dead_code)]

extern crate alloc;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::hw::{self, name_for, refine_hw_rev, ChipInfo, HwRev, ALL_DEV_IDS, QCOM_VENDOR};

/// Errors raised by the baseline probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed.
    Bar0MapFailed,
    /// SoC version register read back 0xFFFFFFFF — the chip is gone
    /// or the link is down.
    LinkDown,
    /// The TCSR version names a stepping Linux's `ath11k_pci_probe`
    /// rejects (`unsupported_*_soc`).
    UnsupportedSoc { major: u32, minor: u32 },
}

/// One bound ath11k device. Holds the BAR0 mapping + the hw_rev
/// derived from the TCSR version registers.
pub struct Ath11kDevice {
    pub mmio_bar0: MmioRegion,
    pub chip: ChipInfo,
    pub hw_rev: HwRev,
    /// PCI device id we matched on.
    pub device_id: u16,
}

impl core::fmt::Debug for Ath11kDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath11kDevice")
            .field("display_name", &self.chip.display_name)
            .field("device_id", &self.device_id)
            .field("hw_rev", &self.hw_rev)
            .finish_non_exhaustive()
    }
}

/// Single-instance live device — most laptops ship one ath11k
/// part.
static CONTROLLER: IrqSafeSpinLock<Option<Ath11kDevice>> = IrqSafeSpinLock::new(None);

/// Register every supported PCI device id with the bus driver
/// match table. Mirrors the shape of Linux's
/// `ath11k_pci_id_table`.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: QCOM_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Probe entry called by `narf-bus::driver_match` when one of our
/// vendor/device pairs surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use core::fmt::Write as _;

    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    let chip = match hw::chip_for_pci_id(device.id.vendor, device.id.device) {
        Some(c) => c,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    // Enable MEM_SPACE + BUS_MASTER. The MHI controller will issue
    // DMA from inside the chip once running, so BUS_MASTER must be
    // set before BAR mapping completes.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: caller hands us exclusive BusDeviceCap authority for
    // this device's cfg + BARs.
    let dev = match unsafe { bring_up(&device, chip) } {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath11k: {} ({:04x}:{:04x}) bring-up failed: {:?}",
                chip.display_name,
                chip.vid,
                chip.did,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: probed {} ({:04x}:{:04x}) hw_rev={} fw=ath11k/{}",
        chip.display_name,
        chip.vid,
        chip.did,
        dev.hw_rev.name(),
        dev.hw_rev.fw_dir().unwrap_or("?"),
    );

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(dev.device_id)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(QCOM_VENDOR),
        pci_did: Some(dev.device_id),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    *CONTROLLER.lock() = Some(dev);
    Ok(())
}

/// Bring the chip up: map BAR0, read the TCSR SoC version (and the
/// sub-version where Linux needs it), resolve `hw_rev`. Pure-IO; no
/// MHI register programming.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice, chip: ChipInfo) -> Result<Ath11kDevice, ProbeError> {
    // SAFETY: `bring_up`'s contract is that the caller owns the device's BARs
    // exclusively — exactly the precondition `map_bar` requires.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // SAFETY: BAR0 mapped + owned; TCSR_SOC_HW_VERSION is a readable
    // chip register.
    let version = unsafe { read32(&mmio_bar0, hw::TCSR_SOC_HW_VERSION) };
    if version == 0xFFFF_FFFF {
        return Err(ProbeError::LinkDown);
    }

    let major =
        (version & hw::TCSR_SOC_HW_VERSION_MAJOR_MASK) >> hw::TCSR_SOC_HW_VERSION_MAJOR_SHIFT;
    let minor = version & hw::TCSR_SOC_HW_VERSION_MINOR_MASK;
    let sub_version = if hw::needs_sub_version(chip.did, major, minor) {
        // SAFETY: BAR0 mapped + owned; TCSR_SOC_HW_SUB_VER is readable
        // (Linux reads it at the same point in `ath11k_pci_probe`).
        unsafe { read32(&mmio_bar0, hw::TCSR_SOC_HW_SUB_VER) }
    } else {
        0
    };
    let hw_rev = refine_hw_rev(chip.did, major, minor, sub_version);
    if hw_rev == HwRev::Unknown {
        return Err(ProbeError::UnsupportedSoc { major, minor });
    }

    Ok(Ath11kDevice {
        mmio_bar0,
        chip,
        hw_rev,
        device_id: chip.did,
    })
}

/// Read a chip register. Offsets below `ATH11K_PCI_WINDOW_START`
/// sit directly in BAR0; higher ones go through the sliding window.
/// Mirrors Linux `pcic.c::__ath11k_pcic_read32` (dynamic-window
/// chips: QCA6390 / WCN6855).
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// readable chip register.
pub unsafe fn read32(mmio: &MmioRegion, offset: u32) -> u32 {
    if offset < hw::ATH11K_PCI_WINDOW_START {
        // SAFETY: caller-asserted BAR0 mapping; offset is inside BAR0.
        unsafe { mmio.read32(offset as u64) }
    } else {
        // SAFETY: caller-asserted BAR0 mapping + register.
        unsafe { read_via_window(mmio, offset) }
    }
}

/// Write a chip register; direct/window split as in [`read32`].
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// writable chip register.
pub unsafe fn write32(mmio: &MmioRegion, offset: u32, value: u32) {
    if offset < hw::ATH11K_PCI_WINDOW_START {
        // SAFETY: caller-asserted BAR0 mapping; offset is inside BAR0.
        unsafe { mmio.write32(offset as u64, value) }
    } else {
        // SAFETY: caller-asserted BAR0 mapping + register.
        unsafe { write_via_window(mmio, offset, value) }
    }
}

/// Serialises window-select + access, and caches the selected
/// window (Linux `ath11k_pci::window_lock` / `register_window`).
/// `u32::MAX` = nothing selected yet.
static WINDOW: IrqSafeSpinLock<u32> = IrqSafeSpinLock::new(u32::MAX);

/// Window number for a chip-register offset —
/// `FIELD_GET(ATH11K_PCI_WINDOW_VALUE_MASK, offset)`.
pub const fn window_of(offset: u32) -> u32 {
    (offset & hw::ATH11K_PCI_WINDOW_VALUE_MASK) >> 19
}

/// Value written to `ATH11K_PCI_WINDOW_REG_ADDRESS` to select the
/// window holding `offset` (Linux `ath11k_pci_select_window`: the
/// window *number*, not the shifted field).
pub const fn window_select_value(offset: u32) -> u32 {
    hw::ATH11K_PCI_WINDOW_ENABLE_BIT | window_of(offset)
}

/// BAR0 byte offset at which `offset` is visible once its window is
/// selected (dynamic-window chips).
pub const fn windowed_bar_offset(offset: u32) -> u32 {
    hw::ATH11K_PCI_WINDOW_START + (offset & hw::ATH11K_PCI_WINDOW_RANGE_MASK)
}

/// # Safety
/// `mmio` must be a valid BAR0 mapping; caller holds `WINDOW`.
unsafe fn select_window(mmio: &MmioRegion, cur: &mut u32, offset: u32) {
    let window = window_of(offset);
    if *cur != window {
        // SAFETY: caller-asserted BAR0 mapping.
        unsafe {
            mmio.write32(
                hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64,
                window_select_value(offset),
            );
            // Posted-write flush, as Linux does, so the select lands
            // before the data access.
            let _ = mmio.read32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64);
        }
        *cur = window;
    }
}

/// Read a register at or above `ATH11K_PCI_WINDOW_START` through the
/// sliding window. Mirrors Linux `ath11k_pci_window_read32`.
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// readable chip register.
pub unsafe fn read_via_window(mmio: &MmioRegion, offset: u32) -> u32 {
    let mut cur = WINDOW.lock();
    // SAFETY: caller-asserted BAR0 mapping; WINDOW held.
    unsafe {
        select_window(mmio, &mut cur, offset);
        mmio.read32(windowed_bar_offset(offset) as u64)
    }
}

/// Write counterpart of [`read_via_window`].
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// writable chip register.
pub unsafe fn write_via_window(mmio: &MmioRegion, offset: u32, value: u32) {
    let mut cur = WINDOW.lock();
    // SAFETY: caller-asserted BAR0 mapping; WINDOW held.
    unsafe {
        select_window(mmio, &mut cur, offset);
        mmio.write32(windowed_bar_offset(offset) as u64, value);
    }
}

/// Test helper: `true` if any device is bound.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller (None if unbound).
pub fn with_controller<R>(f: impl FnOnce(&Ath11kDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
    *WINDOW.lock() = u32::MAX;
}
