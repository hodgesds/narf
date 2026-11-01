// SPDX-License-Identifier: GPL-2.0-or-later
//! Fresh AR9285 HT40 calibration; Linux ar9002_calib.c/calib.c. Unlike HT20,
//! both NF planes and the even/odd ADC gain/DC calibrations must complete.
use super::*;
use crate::ath9k::{
    channel_width::{Geometry, Permission},
    phy::rates::wide::{program_wide, WidePlan},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct WideReport {
    pub(in crate::ath9k) geometry: Geometry,
    pub(in crate::ath9k) report: Report,
    pub(in crate::ath9k) measured_ext_noise_dbm: i16,
    pub(in crate::ath9k) ext_noise_dbm: i16,
    pub(in crate::ath9k) adc: u32,
    pub(in crate::ath9k) powers: WidePlan,
}
impl WideReport {
    pub(in crate::ath9k) fn digest(self) -> [u8; 32] {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF AR9285 actual fresh40 calibration receipt v3");
        hash.update(&self.geometry.body());
        hash.update(&self.report.country);
        hash.update(&self.report.frequency_mhz.to_le_bytes());
        hash.update(&[
            self.report.max_power_half_dbm,
            self.report.pa_offset.unwrap_or(255),
            self.report.iq_i,
            self.report.iq_q as u8,
        ]);
        for value in [
            self.report.measured_noise_dbm,
            self.report.noise_dbm,
            self.measured_ext_noise_dbm,
            self.ext_noise_dbm,
        ] {
            hash.update(&value.to_le_bytes());
        }
        hash.update(&self.adc.to_le_bytes());
        hash.update(&[self.powers.increment]);
        for (register, value) in self.powers.registers {
            hash.update(&register.to_le_bytes());
            hash.update(&value.to_le_bytes());
        }
        hash.finalize()
    }
}
/// # Safety
/// Caller owns the same exclusive parked function after a proven complete
/// old-generation retirement and fresh40 INI/modal/detector/chain/synth setup.
/// Current full40 host/factory and signed full-program qualification cover
/// the calibration itself; no packet DMA or receiver is published yet.
pub(in crate::ath9k) async unsafe fn run(
    owner: &mut Calibration,
    io: &mut impl Io,
    image: &[u8; EEPROM_4K_BYTES],
    permission: Permission,
    xe2: bool,
) -> Result<WideReport, BringUpError> {
    if owner.state != State::New || !permission.geometry.is_wide() {
        return Err(BringUpError::BadState);
    }
    if read(io, 0x981c)? & 1 != 0
        || read(io, 8)? & 4 != 0
        || read(io, 0x840)? & 0x3ff != 0
        || read(io, 0x24)? & 1 != 0
        || read(io, 0x8048)? & 0x0200_0020 != 0x0200_0020
        || read(io, 0x9860)? & 3 != 0
        || read(io, 0x9920)? & 0x10000 != 0
        || read(io, 0x9804)? & 0x7ff != permission.geometry.turbo()
        || read(io, 0x8318)? != 1
    {
        return Err(BringUpError::BadState);
    }
    owner.state = State::Running;
    let attempt = Attempt {
        state: &mut owner.state,
    };
    let powers = program_wide(io, image, permission.geometry, permission.ceiling)?;
    pcie(io, xe2).await?;
    let delay = read(io, 0x9914)? & 0x3fff;
    write(io, 0x981c, 1)?;
    io.settle(u64::from(delay / 10 + 100)).await;
    leakage(io, xe2).await?;
    let pa_offset = if image[31] == 1 {
        None
    } else {
        Some(pa(io).await?)
    };
    let (control, extension) = noise(io).await?;
    let adc = adc(io).await?;
    let (iq_i, iq_q) = iq(io).await?;
    if read(io, 8)? & 4 != 0
        || read(io, 0x840)? & 0x3ff != 0
        || read(io, 0x24)? & 1 != 0
        || read(io, 0x981c)? & 1 != 1
        || read(io, 0x8048)? & 0x0200_0020 != 0x0200_0020
        || read(io, 0x9804)? & 0x7ff != permission.geometry.turbo()
        || read(io, 0x8318)? != 1
        || read(io, 0x99b4)? != adc
    {
        return Err(BringUpError::BadState);
    }
    for (register, value) in powers.registers {
        if read(io, register)? != value {
            return Err(BringUpError::BadCalibration);
        }
    }
    let report = Report {
        country: permission.country,
        frequency_mhz: permission.geometry.control(),
        max_power_half_dbm: permission.ceiling,
        pa_offset,
        iq_i,
        iq_q,
        measured_noise_dbm: control.0,
        noise_dbm: control.1,
    };
    let result = WideReport {
        geometry: permission.geometry,
        report,
        measured_ext_noise_dbm: extension.0,
        ext_noise_dbm: extension.1,
        adc,
        powers,
    };
    owner.report = Some(report);
    *attempt.state = State::Ready;
    Ok(result)
}
async fn carrier_leakage(io: &mut impl Io) -> Result<(), BringUpError> {
    modify(io, 0xa358, 0, 2)?;
    // Source HT40 does not run/toggle the HT20 parallel first phase.
    modify(io, 0x982c, 0x8000, 0)?;
    modify(io, 0x9860, 0, 0x10000)?;
    modify(io, 0xa258, 0, 0x400000)?;
    modify(io, 0x9860, 0, 1)?;
    wait(io, 0x9860, 1, 100000).await?;
    modify(io, 0x982c, 0, 0x8000)?;
    modify(io, 0xa358, 2, 0)?;
    modify(io, 0x9860, 0x10000, 0)
}
async fn leakage(io: &mut impl Io, xe2: bool) -> Result<(), BringUpError> {
    carrier_leakage(io).await?;
    let maximum = (read(io, 0xa274)? & 0x7e000) >> 13;
    let mut gains = 0u32;
    for index in 0..=maximum {
        gains |= 1 << ((read(io, 0xa300 + u64::from(index) * 4)? & 0x1e) >> 1);
    }
    let mut zeros = 0;
    for index in 0..gains.count_ones() {
        let value = read(io, 0xa35c + u64::from(index) * 4)?;
        zeros += u32::from(value & 0x7ff0000 == 0);
        zeros += u32::from((value & 0xffd0) >> 5 == 0);
    }
    if zeros > 1 {
        let original = read(io, 0x7830)?;
        write(
            io,
            0x7830,
            (original & 0xfffff8ff) | if xe2 { 0x500 } else { 0x400 },
        )?;
        carrier_leakage(io).await?;
        write(io, 0x7830, original)?;
    }
    Ok(())
}
async fn noise(io: &mut impl Io) -> Result<((i16, i16), (i16, i16)), BringUpError> {
    let initial = read(io, 0x9860)?;
    for register in [0x9864, 0x99bc] {
        modify(io, register, 0x1ff, ((-118i32 as u32) << 1) & 0x1ff)?;
    }
    if initial & 2 != 0 {
        modify(io, 0x9860, 2, 0)?;
    }
    modify(io, 0x9860, 0x8000, 0)?;
    modify(io, 0x9860, 0x20000, 0)?;
    modify(io, 0x9860, 0, 2)?;
    wait(io, 0x9860, 2, 222000).await?;
    for register in [0x9864, 0x99bc] {
        modify(io, register, 0x1ff, ((-50i32 as u32) << 1) & 0x1ff)?;
    }
    modify(io, 0x9860, 0, 0x8000)?;
    modify(io, 0x9860, 0x20000, 0)?;
    modify(io, 0x9860, 0, 2)?;
    wait(io, 0x9860, 2, 222000).await?;
    let decode = |value: u32, shift: u32| -> Result<(i16, i16), BringUpError> {
        let raw = (((value >> shift) & 0x1ffu32) as i16) << 7 >> 7;
        if raw == 0 {
            return Err(BringUpError::BadCalibration);
        }
        Ok((raw, if raw < -127 { -118 } else { raw.min(-108) }))
    };
    Ok((
        decode(read(io, 0x9864)?, 20)?,
        decode(read(io, 0x99bc)?, 16)?,
    ))
}
async fn adc(io: &mut impl Io) -> Result<u32, BringUpError> {
    let gain = measurements(io, 1).await?;
    if gain[0] == 0 || gain[3] == 0 {
        return Err(BringUpError::BadCalibration);
    }
    // Source arithmetic is native u32; preserve its modulo behavior.
    let i = (gain[1].wrapping_mul(32) / gain[0]) & 63;
    let q = (gain[2].wrapping_mul(32) / gain[3]) & 63;
    let original = read(io, 0x99b4)?;
    let gain_register = original & 0xfffff000 | q | i << 6 | 0x40000000;
    write(io, 0x99b4, gain_register)?;
    if read(io, 0x99b4)? != gain_register {
        return Err(BringUpError::BadCalibration);
    }
    let dc = measurements(io, 2).await?;
    // PER_MAX_LOG_COUNT10, MIN_CAL_SAMPLES1 -> 1 <<15 samples. The I
    // subtraction in Linux is unsigned; Q is signed and truncates toward0.
    let i = (dc[1].wrapping_sub(dc[0]).wrapping_mul(2) / 32768) & 511;
    let q = (dc[2] as i32).wrapping_sub(dc[3] as i32).wrapping_mul(2) / 32768;
    let value = gain_register & 0xc0000fff | ((q as u32 & 511) << 12) | (i << 21) | 0x80000000;
    write(io, 0x99b4, value)?;
    if read(io, 0x99b4)? != value {
        return Err(BringUpError::BadCalibration);
    }
    Ok(value)
}
async fn measurements(io: &mut impl Io, mode: u32) -> Result<[u32; 4], BringUpError> {
    field(io, 0x9920, 0xf000, 12, 10)?;
    write(io, 0x99f0, mode)?;
    modify(io, 0x9920, 0, 0x10000)?;
    wait(io, 0x9920, 0x10000, 30000000).await?;
    Ok([
        read(io, 0x9c10)?,
        read(io, 0x9c14)?,
        read(io, 0x9c18)?,
        read(io, 0x9c1c)?,
    ])
}
