//! PCI facts shared by the built-in binding (`pci.rs`) and the module's
//! (`pci_kabi.rs`): probe errors, the identity register reads, the probe
//! window check, the L1 remap planner, and the per-chip names and
//! firmware files. Moved verbatim from `pci.rs`.
//!
//! References: `drivers/net/wireless/mediatek/mt76/mt7921/pci.c`
//! (`mt7921_pci_probe`, `mt7921_pci_device_table`) and
//! `drivers/net/wireless/mediatek/mt76/mt792x_regs.h`.

use super::regs::*;
use crate::platform::bus::MmioRegion;

/// Errors raised by the Stage-0/Stage-1 probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Current PCI invocation or command-policy validation failed.
    Authority,
    /// The register window cannot contain all required probe accesses.
    UnsupportedRegisterWindow,
    /// The hardware did not latch the requested indirect register page.
    RemapRejected,
    /// Chip identity is not supported by this CONNAC2 implementation.
    UnsupportedChip,
    /// `map_bar_control(device, 0)` failed. Most likely the BAR isn't
    /// implemented (wrong PCI ID matched) or another driver claimed it.
    Bar0MapFailed,
    /// BAR0 reads returned the all-FF sentinel that means "device
    /// gone" — link down or surprise-remove.
    DeviceGone,
    /// Driver-own handshake timed out after `DRV_OWN_RETRY_COUNT`
    /// retries. Either the firmware never released ownership (cold
    /// power-up with no PCIE_BUS_PWR), or the chip is wedged.
    DriverOwnTimeout,
    /// WFSYS reset failed to latch or report initialization complete.
    ResetFailed,
    /// Legacy EFUSE probe error. Discovery leaves MAC unset; the retained
    /// post-firmware path requires a valid firmware-reported MAC.
    EfuseRead,
    /// MCU patch / RAM-code firmware load hit `NotImplemented`. The
    /// firmware-loader path needs the blob to be registered via the
    /// initramfs scan path; absent that, probe still records the
    /// device as bound.
    NotImplemented,
}

/// Validate all identity/power accesses, including the indirect selector.
pub(super) fn validate_probe_window(len: u64) -> Result<(), ProbeError> {
    for addr in [
        MT_PCIE_MAC_INT_ENABLE,
        MT_HW_CHIPID,
        MT_HW_REV,
        MT_HW_BOUND,
        MT_CONN_ON_LPCTL,
    ] {
        super::registers::plan(addr, len).map_err(|_| ProbeError::UnsupportedRegisterWindow)?;
    }
    Ok(())
}

/// # Safety
/// Caller exclusively owns BAR0 and the L1 selector.
pub(super) unsafe fn chip_id_read(mmio: &MmioRegion) -> Result<u32, ProbeError> {
    // SAFETY: forwarded ownership; access validates the complete word.
    unsafe { super::registers::read32(mmio, MT_HW_CHIPID) }.map_err(register_error)
}
/// # Safety
/// Caller exclusively owns BAR0 and the L1 selector.
pub(super) unsafe fn hw_rev_read(mmio: &MmioRegion) -> Result<u32, ProbeError> {
    // SAFETY: forwarded ownership; access validates the complete word.
    unsafe { super::registers::read32(mmio, MT_HW_REV) }.map_err(register_error)
}
/// # Safety
/// Caller exclusively owns BAR0 and the L1 selector.
pub(super) unsafe fn hw_bound_read(mmio: &MmioRegion) -> Result<u32, ProbeError> {
    // SAFETY: forwarded ownership; access validates the complete word.
    unsafe { super::registers::read32(mmio, MT_HW_BOUND) }.map_err(register_error)
}

pub(super) fn register_error(error: super::registers::Error) -> ProbeError {
    match error {
        super::registers::Error::DeviceGone => ProbeError::DeviceGone,
        super::registers::Error::RemapRejected => ProbeError::RemapRejected,
        _ => ProbeError::UnsupportedRegisterWindow,
    }
}

/// Return the checked PCI register offset, or `u32::MAX` if unsupported.
/// An indirect offset alone is not sufficient for I/O: use the checked
/// register transaction, which programs and flushes the L1 selector first.
pub fn l1_remap(abs: u32) -> u32 {
    super::registers::plan(abs, 0x100000).map_or(u32::MAX, |plan| plan.offset)
}

/// Human-readable name for a known device id. Used as the
/// `PciMatch.name` key + the `BoundDriver.name` value.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        MTK_DEV_MT7961 => "mt7921-7961",
        MTK_DEV_MT7922 => "mt7921-7922",
        MTK_DEV_MT7921 => "mt7921-0608",
        // 0616 is a PCI alias for MT7922, not an MT7921 variant. Keep the
        // bound-driver/log label aligned with the firmware and raw chip ID.
        MTK_DEV_MT7921_ALT => "mt7922-0616",
        MTK_DEV_MT7920 => "mt7921-7920",
        _ => "mt7921",
    }
}

/// Resolve the firmware-blob names this chip wants. Returns
/// `(patch_name, ram_code_name)`. Used by the firmware-load stub.
pub fn firmware_blobs_for(did: u16) -> (&'static str, &'static str) {
    match did {
        MTK_DEV_MT7922 | MTK_DEV_MT7921_ALT => (MT7922_ROM_PATCH, MT7922_FIRMWARE_WM),
        MTK_DEV_MT7920 => (MT7920_ROM_PATCH, MT7920_FIRMWARE_WM),
        // MT7921 + MT7961 share the 7961 patch and RAM code.
        _ => (MT7961_ROM_PATCH, MT7961_FIRMWARE_WM),
    }
}
