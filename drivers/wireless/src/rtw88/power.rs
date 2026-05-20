//! RTW88 power-on sequence + chip reset.
//!
//! The "power-on sequence" is Realtek's idiom for a vendor-provided
//! table of `(register, mask, value, delay)` byte writes that walks
//! the PMU/AFE state machine from D3-cold (or POR) into the
//! firmware-ready state. Linux's
//! `drivers/net/wireless/realtek/rtw88/mac.c::rtw_pwr_seq_parser`
//! (Linux v6.6 lines ~140..280) consumes per-chip tables defined in
//! `rtw8821c_table.c` / `rtw8822c_table.c`.
//!
//! For the baseline we don't need the full PMU walk — the chip's
//! power-good handshake is enough to read EFUSE, which is what the
//! caller actually wants. The sequence below is the **minimal**
//! cross-chip prologue every part shares:
//!
//!   1. Clear `REG_RSV_CTRL` (allow writes to the PWR-state regs).
//!   2. Clear `REG_SYS_PW_CTRL` (force PMU to known state).
//!   3. Spin briefly so the AFE settles. Linux uses 0..5 ms of
//!      polled-delay slots in the per-chip tables; 1 ms is the
//!      worst-case settling time documented in the 8822C datasheet
//!      §5.2 "PMU Power-Up Timing".
//!   4. Set `FEN_MREGEN` in `REG_SYS_FUNC_EN` so the MAC block
//!      latches the SYS-clock.
//!   5. Clear `REG_CR` (chip-reset), then write `CR_OPEN` to re-arm
//!      the MAC submodules used by EFUSE access.
//!
//! Full PMU + RF / BB calibration tables are out of scope for the
//! baseline and land alongside firmware loading in a follow-up.

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::regs::*;

/// Errors raised by the baseline power-on path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerError {
    /// The chip never asserted any of the expected ready bits within
    /// the wall-clock budget. Either silicon-absent (BAR window
    /// returned 0xFF) or the part needs the full PWR-seq table that
    /// the baseline doesn't ship.
    Timeout,
    /// Front-of-BAR reads returned the all-FF "device gone" sentinel
    /// — the part isn't really there.
    DeviceGone,
}

/// Sentinel read by the front-of-BAR window when the device has
/// dropped off the link (D3cold / surprise-remove).
const READ_GONE_U16: u16 = 0xFFFF;

/// Run the baseline power-on prologue + chip reset.
///
/// Mirrors the *minimum* of what `rtw88/main.c::rtw_power_on` does
/// before any firmware load: PWR/CR clear, MAC enable, AFE settle,
/// CR rearm.
///
/// # Safety
/// Caller owns the BAR0 MMIO exclusively for the duration of the
/// call.
pub unsafe fn baseline_power_on(mmio: &MmioRegion) -> Result<(), PowerError> {
    // Step 0: presence test. A fresh BAR window on absent silicon
    // returns all-FF on every read. `REG_SYS_FUNC_EN` is the lowest
    // 16-bit register guaranteed to exist regardless of PMU state,
    // so we sample it before issuing writes.
    // SAFETY: identity-mapped MMIO; offset 0x0002 + 2 within BAR0.
    let presence = unsafe { mmio.read16(REG_SYS_FUNC_EN) };
    if presence == READ_GONE_U16 {
        return Err(PowerError::DeviceGone);
    }

    // Step 1: unlock PWR-state registers.
    // SAFETY: same; REG_RSV_CTRL is an 8-bit byte at 0x001C.
    unsafe {
        mmio.write8(REG_RSV_CTRL, 0x00);
    }

    // Step 2: force PMU to a known state by clearing REG_SYS_PW_CTRL.
    // Linux per-chip tables open with a write-0 to this byte.
    // SAFETY: same.
    unsafe {
        mmio.write8(REG_SYS_PW_CTRL, 0x00);
    }

    // Step 3: settle. The PMU needs ~1 ms wall-clock to drop into the
    // baseline state before we touch the SYS regs again. Linux's
    // per-chip tables encode this as a polling slot; we use the
    // deadline-spin helper so on-going sleep_pumps still tick.
    let deadline = Deadline::after_ms(2);
    narf_scheduler::responsive_spin_until(
        || {
            // We don't have a single "ready" bit to wait on at this
            // point — just spin until the deadline.
            // SAFETY: identity-mapped MMIO.
            let _ = unsafe { mmio.read8(REG_SYS_PW_CTRL) };
            false
        },
        deadline,
    );

    // Step 4: enable the MAC sub-block clocks (FEN_MREGEN, bit 15).
    // Linux: `rtw_write16_set(rtwdev, REG_SYS_FUNC_EN, BIT_FEN_MREGEN)`
    // in `rtw_mac_power_switch`. We write the bit unconditionally
    // since baseline doesn't track prior register state.
    // SAFETY: same; 16-bit register at 0x0002 / RFU bit 15.
    unsafe {
        let v = mmio.read16(REG_SYS_FUNC_EN);
        mmio.write16(REG_SYS_FUNC_EN, v | (1 << 15));
    }

    // Step 5: chip-reset via CR. Clear, then write CR_OPEN.
    //   Linux `rtw_mac_init` in `rtw88/mac.c` does the same dance.
    // SAFETY: same; REG_CR is 16-bit at 0x0100.
    unsafe {
        mmio.write16(REG_CR, 0x0000);
    }
    // Brief settle so the chip latches the reset before we re-arm.
    // The HCI / MAC sub-blocks need a few hundred-ns; 1 ms is
    // generous.
    let deadline = Deadline::after_ms(1);
    narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let _ = unsafe { mmio.read16(REG_CR) };
            false
        },
        deadline,
    );
    // SAFETY: same; REG_CR is 16-bit at 0x0100.
    unsafe {
        mmio.write16(REG_CR, CR_OPEN);
    }

    Ok(())
}
