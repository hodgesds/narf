//! ath10k PCI probe + BAR0 mapping + soft-reset.
//!
//! Stage 0 scope:
//!   - Match the QCA988X / 6174 / 6164 / 99X0 / 9377 / 9888 / 9984
//!     PCI IDs (plus the Ubiquiti rebadge of 988X).
//!   - Map BAR0 (the single MMIO register window).
//!   - Read `SOC_CHIP_ID` to confirm we actually have silicon.
//!   - Issue a soft global reset via `SOC_GLOBAL_RESET_ADDRESS`.
//!   - Log `(hw_rev, chip_id, chip_id_rev)` to the kernel console.
//!   - Defer iface registration to a follow-up — `narf_net::iface` is
//!     useful only after the firmware load + WMI handshake, neither of
//!     which Stage 0 attempts. Register a kernel-driver record so
//!     `dmesg` shows the bind.
//!
//! Pattern mirrors `rtw88::pci::probe` for shape (single-instance
//! controller; per-PCI-ID match registration with one name per ID;
//! Cap-gated probe entry).

#![allow(dead_code)]

use core::fmt::Write as _;

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

use super::hw::*;

/// One bound ath10k device. Stage 0 tracks the BAR0 mapping plus
/// the decoded chip identity; the Copy-Engine layout lives in the
/// follow-up.
pub struct Ath10kDevice {
    /// BAR0 MMIO window.
    pub mmio_bar0: MmioRegion,
    /// Decoded hardware family.
    pub hw_rev: HwRev,
    /// Raw 32-bit `SOC_CHIP_ID` register value.
    pub chip_id_raw: u32,
    /// Decoded chip-id-rev (the 4-bit field at bits [11:8]).
    pub chip_id_rev: u32,
    /// PCI device id we matched on.
    pub device_id: u16,
    /// PCI vendor id we matched on.
    pub vendor_id: u16,
}

impl core::fmt::Debug for Ath10kDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kDevice")
            .field("hw_rev", &self.hw_rev)
            .field("chip_id_raw", &format_args!("{:#010x}", self.chip_id_raw))
            .field("chip_id_rev", &self.chip_id_rev)
            .field("vendor_id", &format_args!("{:#06x}", self.vendor_id))
            .field("device_id", &format_args!("{:#06x}", self.device_id))
            .finish_non_exhaustive()
    }
}

/// Errors raised by the Stage 0 bring-up path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// `map_bar(device, 0)` failed. Most likely the BAR isn't
    /// implemented at all (wrong device) or the cap-list claim raced
    /// another driver.
    Bar0MapFailed,
    /// `SOC_CHIP_ID` read returned the all-FF "device gone" sentinel
    /// — the part isn't really there.
    DeviceGone,
    /// Global-reset never released within the deadline.
    ResetTimeout,
    /// The PCI ID matches AR9462, which is ath9k's territory; ath10k
    /// shouldn't bind it. Surfaced explicitly rather than silently
    /// succeeding so the probe trace shows what happened.
    LegacyChipRejected,
}

/// All-FF sentinel for a 32-bit MMIO read on absent silicon.
const READ_GONE_U32: u32 = 0xFFFF_FFFF;

/// Single-instance live device. Same shape as `rtw88` — laptops only
/// ship one ath10k radio, so single-instance is fine for now.
static CONTROLLER: IrqSafeSpinLock<Option<Ath10kDevice>> = IrqSafeSpinLock::new(None);

/// PCI driver match registration. One entry per supported device id,
/// each with a unique `name` so the bus registry doesn't collapse them.
pub fn register_pci_driver() {
    for &(vendor, device) in ALL_PCI_MATCHES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(vendor, device),
            kind: narf_bus::MatchKind::VendorDevice { vendor, device },
            probe,
        });
    }
}

/// Human-readable driver name keyed on the matched `(vendor, device)`.
/// Used as `PciMatch.name` + `BoundDriver.name`. Must be a `'static`
/// string — the bus registry stores it by reference.
pub const fn name_for(vendor: u16, device: u16) -> &'static str {
    match (vendor, device) {
        (ATHEROS_VENDOR, QCA988X_DEVICE_ID) => "ath10k-qca988x",
        (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID) => "ath10k-qca988x-ubnt",
        (ATHEROS_VENDOR, QCA6174_DEVICE_ID) => "ath10k-qca6174",
        (ATHEROS_VENDOR, QCA6164_DEVICE_ID) => "ath10k-qca6164",
        (ATHEROS_VENDOR, QCA99X0_DEVICE_ID) => "ath10k-qca99x0",
        (ATHEROS_VENDOR, QCA9888_DEVICE_ID) => "ath10k-qca9888",
        (ATHEROS_VENDOR, QCA9984_DEVICE_ID) => "ath10k-qca9984",
        (ATHEROS_VENDOR, QCA9377_DEVICE_ID) => "ath10k-qca9377",
        (ATHEROS_VENDOR, AR9462_DEVICE_ID) => "ath10k-ar9462-reject",
        _ => "ath10k",
    }
}

/// Probe entry called by `narf-bus::driver_match` when a matching
/// `(vendor, device)` pair surfaces.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // Refuse re-probe — single-instance for Stage 0.
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }

    // Resolve hw_rev from the PCI ID first so we can refuse AR9462
    // before doing any MMIO.
    let hw_rev = match HwRev::from_pci_id(device.id.vendor, device.id.device) {
        Some(HwRev::Ar9462Legacy) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: AR9462 (1002:0034) is ath9k territory, skipping"
            );
            return Err(narf_bus::ProbeError::NotForThisDriver);
        }
        Some(r) => r,
        None => return Err(narf_bus::ProbeError::NotForThisDriver),
    };

    // Enable MEM_SPACE + BUS_MASTER so BAR reads land + the device
    // can DMA later. Same shape as rtw88.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: bus dispatch hands us exclusive BusDeviceCap authority
    // for this device's cfg + BARs for the lifetime of this call.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let result = unsafe { bring_up(&device, hw_rev) };
    let dev = match result {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  ath10k: bring_up failed for {} ({:04x}:{:04x}): {:?}",
                hw_rev.short_name(),
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    // Log the bind. Mirrors iwlwifi's preamble — single-line summary
    // so dmesg stays readable.
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k: probed {} ({:04x}:{:04x}, chip_id={:#010x} rev={})",
        hw_rev.short_name(),
        dev.vendor_id,
        dev.device_id,
        dev.chip_id_raw,
        dev.chip_id_rev,
    );
    // Tell the operator where to drop the firmware blob. Stage 1 will
    // try to actually load it; Stage 0 just announces the path.
    let _ = writeln!(
        narf_console::Writer,
        "  ath10k:   firmware required at /firmware/ath10k/{}/",
        hw_rev.short_name(),
    );

    let vid = dev.vendor_id;
    let did = dev.device_id;
    *CONTROLLER.lock() = Some(dev);

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(vid, did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(vid),
        pci_did: Some(did),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    Ok(())
}

/// Bring the chip up: map BAR0, identify silicon, soft-reset, decode
/// chip ID. Pure-IO; no CE ring setup, no firmware load.
///
/// # Safety
/// Caller owns the device's BARs exclusively.
pub unsafe fn bring_up(device: &BusDevice, hw_rev: HwRev) -> Result<Ath10kDevice, ProbeError> {
    // SAFETY: caller-asserted BAR exclusivity.
    let mmio_bar0 = unsafe { map_bar(device, 0) }.map_err(|_| ProbeError::Bar0MapFailed)?;

    // Presence test before any writes — the first read of any BAR0
    // register returns all-FF if the device dropped off the link.
    // `SOC_CHIP_ID` is always present; pick it.
    let chip_id_off = soc_chip_id_address(hw_rev);
    // SAFETY: identity-mapped MMIO; `chip_id_off` < 0x100, well inside
    // BAR0 even on the smallest chip.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let pre_reset_chip_id = unsafe { mmio_bar0.read32(chip_id_off) };
    if pre_reset_chip_id == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }

    // SAFETY: BAR0 mapped + owned.
    unsafe { soft_reset(&mmio_bar0)? };

    // Re-read CHIP_ID after the reset so we capture the value the
    // operator-visible log reports. Reset doesn't change it
    // (it's a fuse-backed read-only value) but it's a cheap
    // post-reset presence test.
    // SAFETY: same.
    let chip_id_raw = unsafe { mmio_bar0.read32(chip_id_off) };
    if chip_id_raw == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }
    let rev = chip_id_rev(chip_id_raw);

    Ok(Ath10kDevice {
        mmio_bar0,
        hw_rev,
        chip_id_raw,
        chip_id_rev: rev,
        vendor_id: device.id.vendor,
        device_id: device.id.device,
    })
}

/// Soft-reset the SoC via `SOC_GLOBAL_RESET_ADDRESS`. Mirrors
/// `ath10k/pci.c::ath10k_pci_warm_reset_si0` minus the QCA6174
/// cold/warm dance (which Stage 0 doesn't need — soft-reset alone
/// is enough to land in a known state for CHIP_ID readback).
///
/// Sequence:
///   1. Write the pulse bit to `SOC_GLOBAL_RESET_ADDRESS`.
///   2. Spin until the bit self-clears (chip signals "reset
///      complete" by zeroing the latch). Linux uses a 100 ms
///      budget; we use the same.
///
/// # Safety
/// Caller owns BAR0 exclusively.
pub unsafe fn soft_reset(mmio: &MmioRegion) -> Result<(), ProbeError> {
    // SAFETY: `SOC_GLOBAL_RESET_ADDRESS = 0x0008` < BAR0 size on
    // every ath10k part.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        mmio.write32(SOC_GLOBAL_RESET_ADDRESS, SOC_GLOBAL_RESET_PULSE);
    }

    // Poll for the latch to self-clear. responsive_spin_until ticks
    // sleep_pumps so the FB cursor + serial drain stay alive while we
    // wait (per project_lapic_calibration.md the project's
    // sleep_pump pattern is important).
    let deadline = Deadline::after_ms(100);
    let cleared = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: same.
            let v = unsafe { mmio.read32(SOC_GLOBAL_RESET_ADDRESS) };
            v == 0 || v == READ_GONE_U32
        },
        deadline,
    );
    if !cleared {
        return Err(ProbeError::ResetTimeout);
    }

    // SAFETY: same.
    let post = unsafe { mmio.read32(SOC_GLOBAL_RESET_ADDRESS) };
    if post == READ_GONE_U32 {
        return Err(ProbeError::DeviceGone);
    }

    Ok(())
}

/// Test helper — `true` if the static slot has a bound device.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the bound controller. Returns `None` if probe hasn't run.
pub fn with_controller<R>(f: impl FnOnce(&Ath10kDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// Test-only reset of the bound slot.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
