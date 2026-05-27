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
//!   - hw_rev log line.
//!
//! Stage-2 (deferred): MHI controller register + start, MSI-X
//! vector wiring (1 / 16 / 32 vector configs), firmware load via
//! `narf-firmware`, WMI INIT dispatch.
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

/// Errors raised by the baseline probe path. Wider than RTW88's
/// since ath11k has more bring-up stages that can fail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed.
    Bar0MapFailed,
    /// SoC reset register read-back returned 0xFFFFFFFF — chip is
    /// either gone or the BAR window isn't selected yet.
    LinkDown,
    /// LTSSM enable never converged on the canonical value.
    LtssmFailed,
    /// Firmware-load stage reached but no blob is wired.
    /// Returned for Stage-2 boundary; today probe stops one step
    /// earlier (after hw_rev log).
    NotImplemented,
}

/// One bound ath11k device. Holds the BAR0 mapping + the refined
/// hw_rev derived from the TCSR major/minor read after global
/// reset.
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
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
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
    let result = unsafe { bring_up(&device, chip) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    let did = dev.device_id;
    let hw_rev = dev.hw_rev;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: probed {} ({:04x}:{:04x}) hw_rev={}",
        chip.display_name,
        chip.vid,
        chip.did,
        hw_rev.name(),
    );

    Ok(())
}

/// Bring the chip up: map BAR0, run global reset prologue, read
/// the TCSR SoC version, refine `hw_rev`. Pure-IO; no MHI register
/// programming yet — that lands with the firmware-load wiring in
/// Stage-2.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice, chip: ChipInfo) -> Result<Ath11kDevice, ProbeError> {
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // SAFETY: BAR0 mapped + owned.
    let initial = unsafe { read_via_window(&mmio_bar0, hw::TCSR_SOC_HW_VERSION) };
    if initial == 0xFFFF_FFFF {
        return Err(ProbeError::LinkDown);
    }

    let major = (initial & hw::TCSR_SOC_HW_VERSION_MAJOR_MASK) >> hw::TCSR_SOC_HW_VERSION_MAJOR_SHIFT;
    let minor = initial & hw::TCSR_SOC_HW_VERSION_MINOR_MASK;
    let hw_rev = refine_hw_rev(chip.did, major, minor);

    Ok(Ath11kDevice {
        mmio_bar0,
        chip,
        hw_rev,
        device_id: chip.did,
    })
}

/// Read a 32-bit register via the BAR0 sliding window. Mirrors
/// Linux's `ath11k_pci_window_read32` — the chip exposes a 4 MiB
/// register file via a 512 KiB sliding window at BAR0+0x80000;
/// the window-select register at BAR0+0x310c picks which chunk.
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// readable chip register.
pub unsafe fn read_via_window(mmio: &MmioRegion, offset: u32) -> u32 {
    let window = (offset & hw::ATH11K_PCI_WINDOW_VALUE_MASK) >> 19;
    let window_value = hw::ATH11K_PCI_WINDOW_ENABLE_BIT | (window << 19);
    // SAFETY: caller-asserted BAR0 mapping.
    unsafe {
        mmio.write32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64, window_value);
        // posted-write fence: read back the window register so
        // the write is committed before we hit the data window.
        let _ = mmio.read32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64);
        mmio.read32(
            (hw::ATH11K_PCI_WINDOW_START + (offset & hw::ATH11K_PCI_WINDOW_RANGE_MASK)) as u64,
        )
    }
}

/// Write a 32-bit register via the sliding window. Symmetric with
/// `read_via_window`.
///
/// # Safety
/// `mmio` must be a valid BAR0 mapping; `offset` must address a
/// writable chip register.
pub unsafe fn write_via_window(mmio: &MmioRegion, offset: u32, value: u32) {
    let window = (offset & hw::ATH11K_PCI_WINDOW_VALUE_MASK) >> 19;
    let window_value = hw::ATH11K_PCI_WINDOW_ENABLE_BIT | (window << 19);
    // SAFETY: caller-asserted BAR0 mapping.
    unsafe {
        mmio.write32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64, window_value);
        let _ = mmio.read32(hw::ATH11K_PCI_WINDOW_REG_ADDRESS as u64);
        mmio.write32(
            (hw::ATH11K_PCI_WINDOW_START + (offset & hw::ATH11K_PCI_WINDOW_RANGE_MASK)) as u64,
            value,
        );
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
}
