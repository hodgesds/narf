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

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::pci::l1_remap;
use super::regs::*;

/// Errors raised by the ownership handshake.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    /// Driver-own poll hit `DRV_OWN_RETRY_COUNT` retries without
    /// seeing `OWN_SYNC` clear. Either firmware is wedged or the
    /// chip never got a clock — usually fixed by a PCIe-link cold
    /// reset.
    Timeout,
    /// BAR reads returned the all-FF sentinel mid-handshake. Link
    /// dropped while we were polling.
    DeviceGone,
}

const READ_GONE_U32: u32 = 0xFFFF_FFFF;

/// Read MT_CONN_ON_LPCTL through the L1 remap.
///
/// # Safety
/// Caller owns BAR0 exclusively.
#[inline]
unsafe fn read_lpctl(mmio: &MmioRegion) -> u32 {
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    unsafe { mmio.read32(l1_remap(MT_CONN_ON_LPCTL) as u64) }
}

/// Write MT_CONN_ON_LPCTL through the L1 remap.
///
/// # Safety
/// As `read_lpctl`.
#[inline]
unsafe fn write_lpctl(mmio: &MmioRegion, v: u32) {
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    unsafe { mmio.write32(l1_remap(MT_CONN_ON_LPCTL) as u64, v) }
}

/// Take driver ownership of the PCIe link. Idempotent — if firmware
/// already handed ownership over (cold-boot UEFI path), the first
/// poll iteration sees `OWN_SYNC` already clear and returns success.
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device.
pub unsafe fn take_driver_own(mmio: &MmioRegion) -> Result<(), PowerError> {
    for _ in 0..DRV_OWN_RETRY_COUNT {
        // Tell the link to give ownership to the driver.
        // SAFETY: BAR0 mapped + owned.
        unsafe { write_lpctl(mmio, PCIE_LPCR_HOST_CLR_OWN) };

        // Linux always pauses 2..3 ms after the CLR write when ASPM
        // is in the picture. We don't track ASPM yet; the conservative
        // path is to always pause briefly — it matches `usleep_range`
        // shape and never wedges the handshake.
        let settle = Deadline::after_ms(3);
        narf_scheduler::responsive_spin_until(|| false, settle);

        // Poll OWN_SYNC for clear. 50 ms wall-clock budget per attempt,
        // matching Linux's `mt76_poll_msec_tick(50, 1)`.
        let deadline = Deadline::after_ms(DRV_OWN_POLL_MS);
        let mut last: u32 = 0;
        let cleared = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: BAR0 mapped + owned.
                last = unsafe { read_lpctl(mmio) };
                if last == READ_GONE_U32 {
                    // Surface device-gone as a hard early-out.
                    return true;
                }
                (last & PCIE_LPCR_HOST_OWN_SYNC) == 0
            },
            deadline,
        );

        if last == READ_GONE_U32 {
            return Err(PowerError::DeviceGone);
        }
        if cleared {
            return Ok(());
        }
    }
    Err(PowerError::Timeout)
}

/// Hand ownership back to firmware (entering radio-off / suspend).
///
/// # Safety
/// As `take_driver_own`.
pub unsafe fn give_firmware_own(mmio: &MmioRegion) -> Result<(), PowerError> {
    for _ in 0..DRV_OWN_RETRY_COUNT {
        // SAFETY: BAR0 mapped + owned.
        unsafe { write_lpctl(mmio, PCIE_LPCR_HOST_SET_OWN) };

        // Poll OWN_SYNC for the SET-direction completion (Linux:
        // `mt76_poll_msec_tick(MT_CONN_ON_LPCTL, OWN_SYNC, 4, 50, 1)`
        // — value 4 = BIT(2) set).
        let deadline = Deadline::after_ms(DRV_OWN_POLL_MS);
        let mut last: u32 = 0;
        let set = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: BAR0 mapped + owned.
                last = unsafe { read_lpctl(mmio) };
                if last == READ_GONE_U32 {
                    return true;
                }
                (last & PCIE_LPCR_HOST_OWN_SYNC) != 0
            },
            deadline,
        );

        if last == READ_GONE_U32 {
            return Err(PowerError::DeviceGone);
        }
        if set {
            return Ok(());
        }
    }
    Err(PowerError::Timeout)
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
