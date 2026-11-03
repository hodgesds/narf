// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285 baseband register preparation from Linux ar5008_phy.c,
//! ar9002_phy.c, ar9002_hw.c, ar9002_initvals.h and eeprom_4k.c. Calibration and
//! channel admission are separate stages; PHY activation stays disabled.

use super::{
    channel_width::Geometry,
    identity::{BringUpError, RegisterIo, Registers},
    initvals::*,
    EEPROM_4K_BYTES,
};

/// Registers prepared on a quiescent device, including modal/RF and the
/// EEPROM detector/rate tables and legacy20 mode/chain/synth/slope/spur setup.
/// Live channel authorization and analog calibration remain; PHY stays off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub(in crate::ath9k) geometry: Geometry,
    pub reference_frequency: u16,
    pub high_power_gain: bool,
    pub xe2_gain: bool,
    pub ini_writes: u16,
}

impl Prepared {
    pub fn width_mhz(&self) -> u8 {
        if self.geometry.is_wide() {
            40
        } else {
            20
        }
    }
    pub fn secondary_channel(&self) -> Option<u8> {
        self.geometry.secondary()
    }
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

/// Read back actual stable channel/detector/rate configuration writes on
/// the new per-channel path. Original reference-channel trace stays unchanged.
struct Checked<'a, I: RegisterIo> {
    io: &'a mut I,
    good: bool,
}
impl<I: RegisterIo> RegisterIo for Checked<'_, I> {
    fn authorized(&self) -> bool {
        self.good && self.io.authorized()
    }
    fn read32(&mut self, register: u64) -> u32 {
        if self.good {
            self.io.read32(register)
        } else {
            u32::MAX
        }
    }
    fn write32(&mut self, register: u64, value: u32) {
        if !self.authorized() {
            self.good = false;
            return;
        }
        self.io.write32(register, value);
        self.good = self.io.authorized() && self.io.read32(register) == value;
    }
    fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us);
    }
}
fn prepare(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
) -> Result<Prepared, BringUpError> {
    prepare_at(io, image, 2412)
}
pub(in crate::ath9k) fn prepare_at(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
) -> Result<Prepared, BringUpError> {
    if !(2412..=2472).contains(&frequency) || (frequency - 2412) % 5 != 0 {
        return Err(BringUpError::BadCalibration);
    }
    prepare_geometry(io, image, Geometry::from_frequency(frequency)?)
}
pub(in crate::ath9k) fn prepare_geometry(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    geometry: Geometry,
) -> Result<Prepared, BringUpError> {
    let frequency = geometry.control();
    if geometry.is_wide() && image[6] & 0x2a != 2 {
        return Err(BringUpError::BadCalibration);
    }
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
    let column = if geometry.is_wide() { 3 } else { 4 };
    table(io, AR9285_MODES_9285_1_2, column, &mut writes);
    table(io, gain, column, &mut writes);
    table(io, AR9285_COMMON_9285_1_2, 1, &mut writes);
    // Full-reset INI precedes mode/chain/synth/slope/spur preparation.
    // No fast retune or live PHY activation is implied by this call.
    if !geometry.is_wide() && frequency == 2412 {
        channel::prepare(io, image, frequency)?;
        modal::prepare(io, image, false, false)?;
        power::program(io, image, frequency)?;
        rates::program(io, image, frequency, 0)?;
    } else {
        {
            let mut checked = Checked {
                io: &mut *io,
                good: true,
            };
            channel::prepare_geometry(&mut checked, image, geometry)?;
            if !checked.authorized() {
                return Err(BringUpError::DeviceGone);
            }
        }
        // Modal analog writes retain their source settling sequence. The
        // frequency-dependent stable detector/rate tables are read back below.
        modal::prepare(io, image, geometry.is_wide(), false)?;
        let mut checked = Checked {
            io: &mut *io,
            good: true,
        };
        power::program(&mut checked, image, geometry.center())?;
        if geometry.is_wide() {
            // PHY remains off. A zero conducted budget is preparation only;
            // live full40 permission/qualification replaces it before AGC/RF.
            rates::wide::program_wide(&mut checked, image, geometry, image[60])?;
        } else {
            rates::program(&mut checked, image, frequency, 0)?;
        }
        if !checked.authorized() {
            return Err(BringUpError::DeviceGone);
        }
    }
    // Inactive preparation supplies no positive transmit budget. A later
    // exact-frequency calibration owner must bind current live host policy.
    // Leave PHY, interrupts and packet engines disabled. Live channel/power
    // policy and analog calibration must precede activation.
    io.write32(0x981c, 0);
    io.write32(0x24, 0);
    io.write32(0x8, 0x20);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(Prepared {
        geometry,
        reference_frequency: frequency,
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

pub(super) fn program_at(
    mmio: narf_bus::MmioRegion,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
) -> Result<Prepared, BringUpError> {
    prepare_at(&mut Registers::new(mmio, cap), image, frequency)
}
pub(super) fn program_geometry(
    mmio: narf_bus::MmioRegion,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    image: &[u8; EEPROM_4K_BYTES],
    geometry: Geometry,
) -> Result<Prepared, BringUpError> {
    prepare_geometry(&mut Registers::new(mmio, cap), image, geometry)
}
pub(super) fn program_live_power_at(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
    ceiling: u8,
) -> Result<(), BringUpError> {
    // Full INI/channel/detector preparation already belongs to this exact
    // selected frequency; every factory/CTL/rate limit is re-planned here.
    if frequency == 2412 {
        rates::program(io, image, frequency, ceiling)
    } else {
        rates::checked_plan_at(image, frequency, ceiling)?;
        let mut checked = Checked {
            io: &mut *io,
            good: true,
        };
        rates::program(&mut checked, image, frequency, ceiling)?;
        if checked.authorized() {
            Ok(())
        } else {
            Err(BringUpError::DeviceGone)
        }
    }
}

pub(in crate::ath9k) mod ar9280;
pub(in crate::ath9k) mod ar9287;
mod channel;
mod modal;
mod power;
pub(super) mod rates;
#[cfg(any(test, feature = "kernel-test"))]
mod tests;
