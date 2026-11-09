//! MT7921 MAC / power bring-up.
//!
//! The "MAC" name on CONNAC2 is misleading — this file owns the
//! driver/firmware ownership handshake, not the 802.11 MAC. The
//! 802.11 layer lives behind the MCU; this code's job is to take the
//! link from firmware ownership into driver ownership so the host
//! can talk to the MCU at all.
//!
//! Reference: Linux `drivers/net/wireless/mediatek/mt76/mt792x_core.c`
//! (`__mt792xe_mcu_drv_pmctrl`, `mt792xe_mcu_fw_pmctrl`, around
//! lines 854..924 in v6.6).
//!
//! Sequence (`__mt792xe_mcu_drv_pmctrl`):
//!
//!   1. Write `PCIE_LPCR_HOST_CLR_OWN` (BIT 1) to `MT_CONN_ON_LPCTL`.
//!   2. If ASPM is supported, sleep 2..3 ms.
//!   3. Poll `MT_CONN_ON_LPCTL` for bit `PCIE_LPCR_HOST_OWN_SYNC`
//!      (BIT 2) to clear. Linux uses `mt76_poll_msec_tick(50, 1)`
//!      — 50 ms wall-clock budget per attempt, 1 ms slot.
//!   4. Retry up to `MT792x_DRV_OWN_RETRY_COUNT` (10) times.
//!
//! The reverse (`mt792xe_mcu_fw_pmctrl`) writes `PCIE_LPCR_HOST_SET_OWN`
//! (BIT 0) and polls the same `OWN_SYNC` bit to become 4 (BIT 2 set).
//! We provide both so the suspend path has somewhere to land.

#![allow(dead_code)]

use core::fmt::Write;

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::registers;
use super::regs::*;

/// Errors raised by the ownership handshake.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    /// Register access exceeds the mapped BAR or uses an unsupported address.
    InvalidWindow,
    /// Driver-own poll hit `DRV_OWN_RETRY_COUNT` retries without
    /// seeing `OWN_SYNC` clear. Either firmware is wedged or the
    /// chip never got a clock — usually fixed by a PCIe-link cold
    /// reset.
    Timeout,
    /// BAR reads returned the all-FF sentinel mid-handshake. Link
    /// dropped while we were polling.
    DeviceGone,
    /// WFSYS reset did not latch the requested state.
    ResetRejected,
    /// WFSYS did not report initialization complete after reset release.
    ResetTimeout,
}

struct ProbePower<'a>(&'a MmioRegion);
impl super::mac_power::Io for ProbePower<'_> {
    fn stage(&mut self, stage: super::mac_power::Stage) {
        let _ = writeln!(narf_console::Writer, "  mt7921: probe power {stage:?}");
    }
    fn read(&mut self, address: u32) -> Result<u32, PowerError> {
        // SAFETY: the enclosing probe owns the mapped BAR and L1 selector.
        unsafe { registers::read32(self.0, address) }.map_err(|_| PowerError::InvalidWindow)
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), PowerError> {
        // SAFETY: same current probe invocation and checked register window.
        unsafe { registers::write32(self.0, address, value) }.map_err(|_| PowerError::InvalidWindow)
    }
    fn delay(&mut self, ms: u64) {
        narf_scheduler::responsive_spin_until(|| false, Deadline::after_ms(ms));
    }
    fn poll(
        &mut self,
        address: u32,
        mask: u32,
        expected: u32,
        ms: u64,
    ) -> Result<bool, PowerError> {
        let mut error = None;
        let ready = narf_scheduler::responsive_spin_until(
            || match self.read(address) {
                Ok(u32::MAX) => {
                    error = Some(PowerError::DeviceGone);
                    true
                }
                Ok(value) if value & mask == expected => true,
                Ok(_) => {
                    self.delay(1);
                    false
                }
                Err(failed) => {
                    error = Some(failed);
                    true
                }
            },
            Deadline::after_ms(ms),
        );
        error.map_or(Ok(ready), Err)
    }
}

/// Normalize ownership and reset WFSYS before the first firmware transport.
///
/// # Safety
/// The caller owns BAR0 and its selector under the current PCI invocation,
/// has verified PCI bus mastering is disabled, and has no live DMA owner.
pub(super) unsafe fn initialize_probe(mmio: &MmioRegion) -> Result<(), PowerError> {
    let result = super::mac_power::initialize(&mut ProbePower(mmio));
    if let Err(error) = result {
        if !matches!(error, PowerError::DeviceGone | PowerError::InvalidWindow) {
            // SAFETY: the failed probe still holds the current PCI invocation;
            // mastering remains parked and the checked selector is exclusive.
            let own = unsafe { registers::read32(mmio, MT_CONN_ON_LPCTL) };
            // Only the always-accessible HIF ownership register is safe here.
            // A timeout is not permission to access unowned WFSYS registers.
            let _ = writeln!(
                narf_console::Writer,
                "  mt7921: probe power failed {error:?}: lpctl={own:x?}"
            );
        }
    }
    result
}

/// Take driver ownership of the PCIe link. Idempotent — if firmware
/// already handed ownership over (cold-boot UEFI path), the first
/// poll iteration sees `OWN_SYNC` already clear and returns success.
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device.
pub unsafe fn take_driver_own(mmio: &MmioRegion) -> Result<(), PowerError> {
    super::mac_power::take_driver(&mut ProbePower(mmio))
}

/// Give HIF ownership to firmware through the checked CONN_HOST_CSR window.
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device and selector.
pub unsafe fn give_firmware_own(mmio: &MmioRegion) -> Result<(), PowerError> {
    super::mac_power::give_firmware(&mut ProbePower(mmio))
}

/// Disable PCIe L0s entry while the driver owns the link. Mirrors
/// the `MT_PCIE_MAC_PM |= MT_PCIE_MAC_PM_L0S_DIS` write Linux does
/// in `mt7921e_init_reset` after taking driver ownership.
///
/// # Safety
/// BAR0 mapped + owned; driver-own taken.
pub unsafe fn disable_l0s(mmio: &MmioRegion) {
    // SAFETY: caller-asserted.
    let v = unsafe { mmio.read32(MT_PCIE_MAC_PM as u64) };
    // SAFETY: same.
    unsafe { mmio.write32(MT_PCIE_MAC_PM as u64, v | MT_PCIE_MAC_PM_L0S_DIS) };
}
