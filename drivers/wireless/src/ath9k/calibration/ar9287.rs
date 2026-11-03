// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! AR9287 initial calibration: the non-AR9285 branch of
//! `ar9002_calib.c::ar9002_hw_init_cal` (AGC offset calibration with
//! `FLTR_CAL`, no `OFF_PWDADC` toggle on 9287 1.1+, no CLC/PA), the
//! two-chain `calib.c::ath9k_hw_loadnf`/`_start_nfcal`/`_getnf` with the
//! AR9287 noise-floor limits, and the single-sample per-chain IQ mismatch
//! calibration. ADC gain is never supported on AR9287 (`supp_cals &=
//! ~ADC_GAIN_CAL`); ADC DC runs only on HT40 channels
//! (`ar9002_hw_is_cal_supported`). `ar9287_hw_olc_temp_compensation` is the
//! periodic long-calibration step for the open-loop power owner.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    field, iq_coefficients, measurement_for, modify, pcie, read, wait, write, Attempt, Io,
    Permission, State,
};
use crate::ath9k::{
    chips::MAP_9287,
    identity::{eeprom_word, BringUpError, RegisterIo},
    phy::ar9287::power,
};

/// New-format `AR_SREV` version of AR9287 (`AR_SREV_VERSION_9287`).
const VERSION: u32 = 0x180;
/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_9287_2GHZ`.
const NF_NOMINAL: i16 = -112;
const NF_MIN: i16 = -127;
const NF_MAX: i16 = -97;
/// `ah->nf_regs[0..2]`: `AR_PHY_CCA`, `AR_PHY_CH1_CCA`.
const NF_REGS: [u64; 2] = [0x9864, 0xa864];
/// `AR_PHY_CHAIN_OFFSET` on AR9002.
const CHAIN: u64 = 0x1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub country: [u8; 2],
    pub frequency_mhz: u16,
    pub max_power_half_dbm: u8,
    pub rx_chainmask: u8,
    /// `ah->initPDADC` retained for `olc_temp_compensation`.
    pub init_pdadc: u8,
    /// Per-chain `(iCoff, qCoff)` for chains `0..popcount(rx_chainmask)`.
    pub iq: [Option<(u8, i8)>; 2],
    /// `ar9002_hw_do_getnf` readings before and after `ath9k_hw_nf_sanitize`.
    pub measured_noise_dbm: [Option<i16>; 2],
    pub noise_dbm: [Option<i16>; 2],
}

#[derive(Debug)]
pub(in crate::ath9k) struct Calibration {
    state: State,
    report: Option<Report>,
}
impl Default for Calibration {
    fn default() -> Self {
        Self {
            state: State::New,
            report: None,
        }
    }
}
impl Calibration {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn report(&self) -> Option<Report> {
        self.report
    }
    /// # Safety
    /// Exclusive identified AR9287 after `phy::ar9287::prepare` for the
    /// permission's frequency. PCI BME off, no published packet DMA,
    /// MAC/TX/IRQ parked. Owner and exact factory map survive cancellation;
    /// a new attempt requires an independently proved complete reset.
    pub(in crate::ath9k) async unsafe fn run(
        &mut self,
        io: &mut impl Io,
        image: &[u8],
        rx_chainmask: u8,
        permission: Permission,
    ) -> Result<Report, BringUpError> {
        if self.state != State::New {
            return Err(BringUpError::BadState);
        }
        if image.len() != MAP_9287.bytes() || !MAP_9287.chainmask_valid(rx_chainmask) {
            return Err(BringUpError::BadIdentity);
        }
        if read(io, 0x981c)? & 1 != 0
            || read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
            || read(io, 0x9860)? & 3 != 0
            || read(io, 0x9920)? & 0x10000 != 0
        {
            return Err(BringUpError::BadState);
        }
        self.state = State::Running;
        let attempt = Attempt {
            state: &mut self.state,
        };
        // Factory targets, two-chain CTL and the signed ceiling are
        // intersected before the PHY is activated.
        let plan = power::program(io, image, permission.frequency, permission.ceiling)?;
        // ar9002_hw_configpcipowersave: AR9287 shares the AR9280 SerDes
        // table and the AR9285_WA_DEFAULT | BIT6 | BIT7 workaround word.
        pcie(io, false).await?;
        // ar5008_hw_init_bb: 2 GHz OFDM synth delay is RX_DELAY / 10 + 100.
        let delay = read(io, 0x9914)? & 0x3fff;
        write(io, 0x981c, 1)?;
        io.settle(u64::from(delay / 10 + 100)).await;
        agc(io).await?;
        let (measured_noise_dbm, noise_dbm) = noise(io, rx_chainmask).await?;
        let iq = iq(io, rx_chainmask).await?;
        if read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x981c)? & 1 != 1
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
        {
            return Err(BringUpError::BadState);
        }
        let report = Report {
            country: permission.country,
            frequency_mhz: permission.frequency,
            max_power_half_dbm: permission.ceiling,
            rx_chainmask,
            init_pdadc: plan.init_pdadc,
            iq,
            measured_noise_dbm,
            noise_dbm,
        };
        self.report = Some(report);
        *attempt.state = State::Ready;
        Ok(report)
    }
}

/// `ar9002_hw_init_cal` for AR_SREV_9280_20_OR_LATER and 9287 1.1+:
/// `FLTR_CAL` brackets the AGC offset calibration, polled for
/// `AH_WAIT_TIMEOUT`.
async fn agc(io: &mut impl Io) -> Result<(), BringUpError> {
    modify(io, 0x9860, 0, 0x10000)?;
    modify(io, 0x9860, 0, 1)?;
    wait(io, 0x9860, 1, 100_000).await?;
    modify(io, 0x9860, 0x10000, 0)
}

fn nf_field(value: i16) -> u32 {
    ((value as u32) << 1) & 0x1ff
}

/// `ath9k_hw_loadnf` (history at its `nominal` initial value), the -50
/// maxCCA restore, `ath9k_hw_start_nfcal(update)`, then the completed
/// `ar9002_hw_do_getnf` readings with `ath9k_hw_nf_sanitize`.
async fn noise(
    io: &mut impl Io,
    rx_chainmask: u8,
) -> Result<([Option<i16>; 2], [Option<i16>; 2]), BringUpError> {
    let chains = || (0..2usize).filter(move |c| rx_chainmask & (1 << *c) != 0);
    let initial = read(io, 0x9860)?;
    for chain in chains() {
        modify(io, NF_REGS[chain], 0x1ff, nf_field(NF_NOMINAL))?;
    }
    if initial & 2 != 0 {
        modify(io, 0x9860, 2, 0)?;
    }
    modify(io, 0x9860, 0x8000, 0)?;
    modify(io, 0x9860, 0x20000, 0)?;
    modify(io, 0x9860, 0, 2)?;
    wait(io, 0x9860, 2, 222_000).await?;
    if initial & 2 != 0 {
        if initial & 0x8000 != 0 {
            modify(io, 0x9860, 0, 0x8000)?;
        }
        if initial & 0x20000 != 0 {
            modify(io, 0x9860, 0, 0x20000)?;
        }
        modify(io, 0x9860, 0, 2)?;
    }
    for chain in chains() {
        modify(io, NF_REGS[chain], 0x1ff, nf_field(-50))?;
    }
    modify(io, 0x9860, 0, 0x8000)?;
    modify(io, 0x9860, 0x20000, 0)?;
    modify(io, 0x9860, 0, 2)?;
    wait(io, 0x9860, 2, 222_000).await?;
    let mut measured = [None; 2];
    let mut applied = [None; 2];
    // Chain 0 is always read; chain 1 only when it receives.
    for chain in [0, 1] {
        if chain == 1 && rx_chainmask & 2 == 0 {
            break;
        }
        let raw = ((read(io, NF_REGS[chain])? >> 20) & 0x1ff) as i16;
        let raw = (raw << 7) >> 7;
        if raw == 0 {
            return Err(BringUpError::BadCalibration);
        }
        measured[chain] = Some(raw);
        applied[chain] = Some(if raw > NF_MAX {
            NF_MAX
        } else if raw < NF_MIN {
            NF_NOMINAL
        } else {
            raw
        });
    }
    Ok((measured, applied))
}

/// `iq_cal_single_sample`: `ar9002_hw_setup_calibration` (log count
/// `PER_MAX_LOG_COUNT`, `AR_PHY_CALMODE_IQ`, `DO_CAL`), one collected sample,
/// then `ar9002_hw_iqcalibrate` over chains `0..numChains` and the chain-0
/// `IQCORR_ENABLE`.
async fn iq(io: &mut impl Io, rx_chainmask: u8) -> Result<[Option<(u8, i8)>; 2], BringUpError> {
    field(io, 0x9920, 0xf000, 12, 10)?;
    write(io, 0x99f0, 0)?;
    modify(io, 0x9920, 0, 0x10000)?;
    wait(io, 0x9920, 0x10000, 30_000_000).await?;
    let chains = rx_chainmask.count_ones() as usize;
    let mut measured = [(0u32, 0u32, 0u32); 2];
    for (chain, slot) in measured.iter_mut().enumerate().take(chains) {
        let at = chain as u64 * CHAIN;
        *slot = (
            measurement_for(io, 0x9c10 + at, VERSION)?,
            measurement_for(io, 0x9c14 + at, VERSION)?,
            measurement_for(io, 0x9c18 + at, VERSION)?,
        );
    }
    // Validate every chain before the first correction write.
    let mut out = [None; 2];
    for (chain, (i, q, correlation)) in measured.into_iter().enumerate().take(chains) {
        out[chain] = Some(iq_coefficients(i, q, correlation)?);
    }
    for (chain, coefficients) in out.iter().enumerate() {
        let Some((i, q)) = coefficients else { continue };
        let at = 0x9920 + chain as u64 * CHAIN;
        field(io, at, 0x7e0, 5, u32::from(*i))?;
        field(io, at, 0x1f, 0, *q as u32)?;
    }
    modify(io, 0x9920, 0, 0x800)?;
    Ok(out)
}

/// `adc_dc_cal_single_sample` for HT40 channels: `AR_PHY_CALMODE_ADC_DC_PER`
/// then `ar9002_hw_adc_dccal_calibrate`, whose u32 arithmetic over
/// `numSamples = (1 << (10 + 5)) * 1` is kept exactly.
pub(in crate::ath9k) async fn adc_dc(
    io: &mut impl Io,
    rx_chainmask: u8,
) -> Result<[Option<(u16, u16)>; 2], BringUpError> {
    field(io, 0x9920, 0xf000, 12, 10)?;
    write(io, 0x99f0, 2)?;
    modify(io, 0x9920, 0, 0x10000)?;
    wait(io, 0x9920, 0x10000, 30_000_000).await?;
    let mut out = [None; 2];
    for (chain, slot) in out
        .iter_mut()
        .enumerate()
        .take(rx_chainmask.count_ones() as usize)
    {
        let at = chain as u64 * CHAIN;
        let i_odd = measurement_for(io, 0x9c10 + at, VERSION)?;
        let i_even = measurement_for(io, 0x9c14 + at, VERSION)?;
        let q_odd = measurement_for(io, 0x9c18 + at, VERSION)?;
        let q_even = measurement_for(io, 0x9c1c + at, VERSION)?;
        *slot = Some(adc_dc_mismatch(i_odd, i_even, q_odd, q_even));
    }
    for (chain, mismatch) in out.iter().enumerate() {
        let Some((i, q)) = mismatch else { continue };
        modify(
            io,
            0x99b4 + chain as u64 * CHAIN,
            !0xc000_0fff,
            (u32::from(*q) << 12) | (u32::from(*i) << 21),
        )?;
    }
    modify(io, 0x99b4, 0, 0x8000_0000)?;
    Ok(out)
}

/// `(iDcMismatch, qDcMismatch)` of `ar9002_hw_adc_dccal_calibrate`.
pub(in crate::ath9k) fn adc_dc_mismatch(
    i_odd: u32,
    i_even: u32,
    q_odd: u32,
    q_even: u32,
) -> (u16, u16) {
    let samples = 1u32 << 15;
    let i = (i_even.wrapping_sub(i_odd).wrapping_mul(2) / samples) & 0x1ff;
    let q = (q_odd.wrapping_sub(q_even).wrapping_mul(2) / samples) & 0x1ff;
    (i as u16, q as u16)
}

/// `ar9287_hw_olc_temp_compensation`: the PD average against `initPDADC`,
/// scaled by `tempSensSlope` (EEPROM minor >= 2, else 0 so no correction),
/// written to both chains' `OLPC_TEMP_COMP`. Returns the applied delta, or
/// `None` while no frame has been transmitted (no write, as Linux).
pub(in crate::ath9k) fn olc_temp_compensation(
    io: &mut impl RegisterIo,
    image: &[u8],
    init_pdadc: u8,
) -> Result<Option<i32>, BringUpError> {
    if image.len() != MAP_9287.bytes() {
        return Err(BringUpError::BadLength);
    }
    let current = ((read(io, 0xa264)? & 0x1fe) >> 1) as i32;
    if init_pdadc == 0 || current == 0 {
        return Ok(None);
    }
    let slope = if eeprom_word(image, 4) & 0xfff >= 2 {
        i32::from(image[33] as i8)
    } else {
        0
    };
    let delta = if slope == 0 {
        0
    } else {
        ((current - i32::from(init_pdadc)) * 4) / slope
    };
    for register in [0xa398, 0xb398] {
        field(io, register, 0xfc00, 10, delta as u32)?;
    }
    Ok(Some(delta))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
