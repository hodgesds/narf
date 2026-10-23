// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 baseband register preparation from Linux ar5008_phy.c,
//! ar9002_phy.c, ar9002_hw.c, ar9002_initvals.h and eeprom_4k.c. Calibration and
//! channel admission are separate stages; PHY activation stays disabled.

use super::{
    identity::{BringUpError, RegisterIo, Registers},
    initvals::*,
    EEPROM_4K_BYTES,
};

/// Registers prepared on a quiescent device, including modal/RF and the
/// EEPROM detector table. CTL/rate power and calibration remain; PHY stays off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub reference_frequency: u16,
    pub high_power_gain: bool,
    pub xe2_gain: bool,
    pub ini_writes: u16,
}

pub(super) const REQUIRED_BAR: u64 = 0xd388;

fn rmw(io: &mut impl RegisterIo, register: u64, clear: u32, set: u32) -> Result<(), BringUpError> {
    let value = io.read32(register);
    if value == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(register, (value & !clear) | set);
    Ok(())
}

fn table<const C: usize>(
    io: &mut impl RegisterIo,
    rows: &[[u32; C]],
    column: usize,
    count: &mut u16,
) {
    for row in rows {
        io.write32(u64::from(row[0]), row[column]);
        if (0x7800..0x78a0).contains(&row[0]) {
            io.delay_us(100);
        }
        *count += 1;
        if *count % 64 == 0 {
            io.delay_us(1);
        }
    }
}

fn prepare(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
) -> Result<Prepared, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    // SYNTH9 identifies the XE2 variant; SREV's revision nibble does not.
    let synth9 = io.read32(0x7868);
    if synth9 == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    let xe2 = synth9 & 7 == 1;
    let high = image[31] == 1; // baseEepHeader.txGainType.
    let gain = match (xe2, high) {
        (false, false) => AR9285_MODES_ORIGINAL_TX_GAIN_9285_1_2,
        (false, true) => AR9285_MODES_HIGH_POWER_TX_GAIN_9285_1_2,
        (true, false) => AR9285_MODES_XE2_0_NORMAL_POWER,
        (true, true) => AR9285_MODES_XE2_0_HIGH_POWER,
    };

    io.write32(0x24, 0); // AR_IER_DISABLE.
    io.write32(0x880, 0x3ff); // Disable all ten TX queues.
    io.write32(0x8, 0x20); // AR_CR_RXD, never RXE.
    rmw(io, 0x8048, 0, 0x02000020)?; // RX_ABORT | RX_DIS.
    io.write32(0x981c, 0); // AR_PHY_ACTIVE_DIS.
    io.write32(0x7014, (5 << 10) | 0x2c); // 2GHz, full-rate PLL.
    io.delay_us(100);
    io.write32(0x7048, 2); // AR_RTC_FORCE_DERIVED_CLK.
    io.write32(0x9800, 7);
    io.write32(0x9830, 1); // External analog shift selection.
    io.write32(0x9830, 0); // AR9285 has no separate ADDAC table.
    let mut writes = 0;
    table(io, AR9285_MODES_9285_1_2, 4, &mut writes); // 2GHz HT20.
    table(io, gain, 4, &mut writes);
    table(io, AR9285_COMMON_9285_1_2, 1, &mut writes);
    // The common INI deliberately clears DIAG_SW; keep receive blocked.
    rmw(io, 0x8048, 0, 0x02000020)?;
    io.write32(0xa200, 4); // AR_PHY_MODE_DYNAMIC.
    rmw(io, 0xa204, 0x10, 0)?; // Reference channel is not Japan channel 14.
    let synth = io.read32(0x9874);
    if synth == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(
        0x9874,
        (synth & 0xc0000000) | (1 << 29) | (1 << 28) | ((2412 * 0x10000) / 15),
    );
    modal::prepare(io, image, false, false)?;
    power::program(io, image, 2412)?;
    // Leave PHY, interrupts and packet engines disabled. CTL/rate-power
    // policy and analog calibration must precede activation.
    io.write32(0x981c, 0);
    io.write32(0x24, 0);
    io.write32(0x8, 0x20);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(Prepared {
        reference_frequency: 2412,
        high_power_gain: high,
        xe2_gain: xe2,
        ini_writes: writes,
    })
}

pub(super) fn program(
    mmio: narf_bus::MmioRegion,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    image: &[u8; EEPROM_4K_BYTES],
) -> Result<Prepared, BringUpError> {
    prepare(&mut Registers::new(mmio, cap), image)
}

mod modal;
mod power;
#[cfg(any(test, feature = "kernel-test"))]
mod tests;
