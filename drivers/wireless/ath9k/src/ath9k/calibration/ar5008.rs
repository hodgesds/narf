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
//! AR5416/AR5418 and AR9160 (AR5008 PHY ops) calibration for one 20 MHz
//! channel in either band.
//!
//! `ar9002_calib.c::ar9002_hw_init_cal` below AR9280_20 is the plain AGC
//! offset calibration (no `FLTR_CAL`, no `OFF_PWDADC` toggle, no CLC/PA).
//! The noise floor uses `ar5008_phy.c::ar5008_hw_do_getnf`
//! (`AR_PHY_MINCCA_PWR` bits 19..27 of `AR_PHY_CCA`/`CH1_CCA`/`CH2_CCA`) and
//! `ar5008_hw_set_nf_limits`. `ar9002_hw_init_cal_settings` gives AR5416 no
//! per-calibration at all (`supp_cals` stays 0, no list: no IQ) and AR9160
//! the multi-sample set (`iq_cal_multi_sample`: `MAX_CAL_SAMPLES` 64 samples
//! at `PER_MIN_LOG_COUNT` 2). ADC gain and ADC DC are in AR9160's
//! `supp_cals` but `ar9002_hw_is_cal_supported` runs them on HT40 only, so
//! neither runs on this 20 MHz owner. `ath9k_hw_reset_calvalid` returns
//! early below AR9160. There is no open-loop temperature step (closed-loop
//! maps only).
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    ar9287::Limits, field, iq_coefficients, measurement_for, modify, read, wait, write, Attempt,
    Io, Permission, State,
};
use crate::ath9k::{
    chips::{Chip, AR_SREV_VERSION_9160, MAP_DEF},
    identity::{BringUpError, Identity, RegisterIo},
    phy::{ar9280::power, Tune},
};

/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_5416_2GHZ`.
pub(in crate::ath9k) const LIMITS_2GHZ: Limits = Limits {
    nominal: -90,
    min: -100,
    max: -80,
};
/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_5416_5GHZ`.
pub(in crate::ath9k) const LIMITS_5GHZ: Limits = Limits {
    nominal: -100,
    min: -110,
    max: -90,
};
/// `ar5416_cca_regs[0..3]`: `AR_PHY_CCA`, `AR_PHY_CH1_CCA`, `AR_PHY_CH2_CCA`.
const NF_REGS: [u64; 3] = [0x9864, 0xa864, 0xb864];
/// `AR5416_MAX_CHAINS`.
const CHAINS: usize = 3;
/// `AR_PHY_CHAIN_OFFSET`: `AR_PHY_TIMING_CTRL4(i)` / `AR_PHY_CAL_MEAS_n(i)`
/// are `base + (i << 12)`.
const CHAIN: u64 = 0x1000;
/// `calib.h` `MAX_CAL_SAMPLES` and `PER_MIN_LOG_COUNT`.
pub(in crate::ath9k) const MAX_CAL_SAMPLES: u32 = 64;
const PER_MIN_LOG_COUNT: u32 = 2;
/// `AR9002_CAL_MAX_TIME` (30 s), measured from `ath9k_hw_reset_calibration`.
const CAL_MAX_US: u64 = 30_000_000;

/// `ath9k_hw_get_nf_limits` (`ah->nf_2g` / `ah->nf_5g`) for the tune's band.
pub(in crate::ath9k) fn limits(tune: Tune) -> Limits {
    limits_for(tune.is_5ghz())
}
fn limits_for(five: bool) -> Limits {
    if five {
        LIMITS_5GHZ
    } else {
        LIMITS_2GHZ
    }
}

/// Whether `ar9002_hw_init_cal_settings` gives the chip the IQ mismatch
/// calibration (`AR_SREV_9160_10_OR_LATER`).
fn has_iq(chip: Chip) -> bool {
    chip == Chip::Ar9160
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Report {
    pub chip: Chip,
    pub country: [u8; 2],
    pub frequency_mhz: u16,
    pub five_ghz: bool,
    pub max_power_half_dbm: u8,
    pub rx_chainmask: u8,
    /// AR9160 per-chain `(iCoff, qCoff)` for chains
    /// `0..popcount(rx_chainmask)` (Linux's `numChains`); `None` on AR5416.
    pub iq: [Option<(u8, i8)>; CHAINS],
    /// `ar5008_hw_do_getnf` readings before and after `ath9k_hw_nf_sanitize`
    /// (chain 0 always, chains 1/2 when they receive).
    pub measured_noise_dbm: [Option<i16>; CHAINS],
    pub noise_dbm: [Option<i16>; CHAINS],
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
    /// `aspm` is Linux's `ah->aspm_enabled` (only the PCIe AR5418 `0x0024`
    /// can have it): `ath9k_start` → `ath9k_hw_configpcipowersave(ah,
    /// false)` writes the pre-AR9280 SerDes words and `AR_WA_DEFAULT`.
    ///
    /// # Safety
    /// Exclusive identified AR5416/AR5418/AR9160 after `phy::ar5008::prepare`
    /// for `tune` at the permission's frequency. PCI BME off, no published
    /// packet DMA, MAC/TX/IRQ parked. Owner and exact factory map survive
    /// cancellation; a new attempt requires an independently proved
    /// complete reset.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::ath9k) async unsafe fn run(
        &mut self,
        io: &mut impl Io,
        chip: Chip,
        identity: &Identity,
        image: &[u8],
        tune: Tune,
        rx_chainmask: u8,
        aspm: bool,
        permission: Permission,
    ) -> Result<Report, BringUpError> {
        if self.state != State::New {
            return Err(BringUpError::BadState);
        }
        if !matches!(chip, Chip::Ar5416 | Chip::Ar9160) {
            return Err(BringUpError::UnsupportedRevision);
        }
        if image.len() != MAP_DEF.bytes()
            || !(1..=7).contains(&rx_chainmask)
            || rx_chainmask & !identity.rx_chainmask != 0
        {
            return Err(BringUpError::BadIdentity);
        }
        if tune.is_wide() || tune.center() != permission.frequency {
            return Err(BringUpError::Policy);
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
        // Closed-loop def targets (three-chain correction), per-band CTL
        // and the ceiling are intersected before the PHY is activated.
        power::program_chip(io, identity, image, tune, permission.ceiling, chip)?;
        crate::ath9k::pcie_pm::configure_ar5008(io, aspm, false)?;
        // ar5008_hw_init_bb: OFDM synth delay RX_DELAY / 10 + 100 us.
        let delay = read(io, 0x9914)? & 0x3fff;
        write(io, 0x981c, 1)?;
        io.settle(u64::from(delay / 10 + 100)).await;
        agc(io).await?;
        let (measured_noise_dbm, noise_dbm) = noise(io, rx_chainmask, limits(tune)).await?;
        let iq = if has_iq(chip) {
            iq_multi(io, rx_chainmask).await?
        } else {
            [None; CHAINS]
        };
        if read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x981c)? & 1 != 1
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
        {
            return Err(BringUpError::BadState);
        }
        let report = Report {
            chip,
            country: permission.country,
            frequency_mhz: permission.frequency,
            five_ghz: tune.is_5ghz(),
            max_power_half_dbm: permission.ceiling,
            rx_chainmask,
            iq,
            measured_noise_dbm,
            noise_dbm,
        };
        self.report = Some(report);
        *attempt.state = State::Ready;
        Ok(report)
    }
}

/// `ar9002_hw_init_cal` below AR9280_20: `AR_PHY_AGC_CONTROL |= CAL`, then
/// poll CAL clear for `AH_WAIT_TIMEOUT`. No `FLTR_CAL`, no `OFF_PWDADC`.
pub(in crate::ath9k) async fn agc(io: &mut impl Io) -> Result<(), BringUpError> {
    let value = read(io, 0x9860)?;
    write(io, 0x9860, value | 1)?;
    wait(io, 0x9860, 1, 100_000).await
}

fn nf_field(value: i16) -> u32 {
    ((value as u32) << 1) & 0x1ff
}

/// `ar5008_hw_do_getnf` for one control chain: `AR_PHY_MINCCA_PWR`
/// (`0x0ff80000`, shift 19), sign-extended from 9 bits.
fn minimum_cca(io: &mut impl RegisterIo, chain: usize) -> Result<i16, BringUpError> {
    let raw = ((read(io, NF_REGS[chain])? >> 19) & 0x1ff) as i16;
    Ok((raw << 7) >> 7)
}

/// `ath9k_hw_loadnf` at the nominal history, `ath9k_hw_start_nfcal(true)`
/// and (as the AR9002 owners do) the completed `ar5008_hw_do_getnf`
/// readings with `ath9k_hw_nf_sanitize` over the three control chains.
pub(in crate::ath9k) async fn noise(
    io: &mut impl Io,
    rx_chainmask: u8,
    limits: Limits,
) -> Result<([Option<i16>; CHAINS], [Option<i16>; CHAINS]), BringUpError> {
    let chains = || (0..CHAINS).filter(move |c| rx_chainmask & (1 << *c) != 0);
    let initial = read(io, 0x9860)?;
    for chain in chains() {
        modify(io, NF_REGS[chain], 0x1ff, nf_field(limits.nominal))?;
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
    let mut measured = [None; CHAINS];
    let mut applied = [None; CHAINS];
    for chain in 0..CHAINS {
        if chain != 0 && rx_chainmask & (1 << chain) == 0 {
            continue;
        }
        let raw = minimum_cca(io, chain)?;
        if raw == 0 {
            return Err(BringUpError::BadCalibration);
        }
        measured[chain] = Some(raw);
        applied[chain] = Some(limits.sanitize(raw));
    }
    Ok((measured, applied))
}

/// `ar9002_hw_setup_calibration` for `iq_cal_multi_sample`:
/// `IQCAL_LOG_COUNT_MAX = PER_MIN_LOG_COUNT`, `AR_PHY_CALMODE_IQ`, `DO_CAL`.
fn setup_iq(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    field(io, 0x9920, 0xf000, 12, PER_MIN_LOG_COUNT)?;
    write(io, 0x99f0, 0)?;
    modify(io, 0x9920, 0, DO_CAL)
}

/// `ah->totalPowerMeasI/Q` and `totalIqCorrMeas` over the collected samples
/// (u32 / int32 accumulation, wrapping as the C sums do).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct IqTotals {
    pub power_i: [u32; CHAINS],
    pub power_q: [u32; CHAINS],
    pub correlation: [u32; CHAINS],
}

/// `ar9002_hw_iqcal_collect`: all `AR5416_MAX_CHAINS` chains, whatever the
/// mask.
fn collect(io: &mut impl RegisterIo, totals: &mut IqTotals) -> Result<(), BringUpError> {
    for chain in 0..CHAINS {
        let at = chain as u64 * CHAIN;
        let i = measurement_for(io, 0x9c10 + at, AR_SREV_VERSION_9160)?;
        let q = measurement_for(io, 0x9c14 + at, AR_SREV_VERSION_9160)?;
        let c = measurement_for(io, 0x9c18 + at, AR_SREV_VERSION_9160)?;
        totals.power_i[chain] = totals.power_i[chain].wrapping_add(i);
        totals.power_q[chain] = totals.power_q[chain].wrapping_add(q);
        totals.correlation[chain] = totals.correlation[chain].wrapping_add(c);
    }
    Ok(())
}

/// `ar9002_hw_iqcalibrate(ah, numChains)` over the totals: each chain
/// whose denominators are non-zero gets its coefficients, then chain 0
/// `IQCORR_ENABLE`. `numChains` is the popcount of the RX mask, so a 0x5
/// mask corrects chains 0 and 1 exactly as Linux does.
fn iqcalibrate(
    io: &mut impl RegisterIo,
    rx_chainmask: u8,
    totals: &IqTotals,
) -> Result<[Option<(u8, i8)>; CHAINS], BringUpError> {
    let chains = rx_chainmask.count_ones() as usize;
    let mut out = [None; CHAINS];
    for (chain, slot) in out.iter_mut().enumerate().take(chains) {
        *slot = iq_coefficients(
            totals.power_i[chain],
            totals.power_q[chain],
            totals.correlation[chain],
        )
        .ok();
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

/// The AR9160 initial `iq_cal_multi_sample` run to completion:
/// `ath9k_hw_reset_calibration` (totals and `cal_samples` zeroed), then 64
/// rounds of DO_CAL completion → collect → re-setup, all inside one
/// `AR9002_CAL_MAX_TIME` from the first setup, then the post-processing.
/// Every receiving chain must produce coefficients.
pub(in crate::ath9k) async fn iq_multi(
    io: &mut impl Io,
    rx_chainmask: u8,
) -> Result<[Option<(u8, i8)>; CHAINS], BringUpError> {
    let start = io.now_us();
    let mut totals = IqTotals::default();
    setup_iq(io)?;
    let mut samples = 0;
    loop {
        let spent = io.now_us().saturating_sub(start);
        wait(io, 0x9920, DO_CAL, CAL_MAX_US.saturating_sub(spent)).await?;
        collect(io, &mut totals)?;
        samples += 1;
        if samples >= MAX_CAL_SAMPLES {
            break;
        }
        setup_iq(io)?;
    }
    let chains = rx_chainmask.count_ones() as usize;
    // Validate every chain before the first correction write.
    for chain in 0..chains {
        iq_coefficients(
            totals.power_i[chain],
            totals.power_q[chain],
            totals.correlation[chain],
        )?;
    }
    iqcalibrate(io, rx_chainmask, &totals)
}

/// `ath9k.h` `ATH_STA_SHORT_CALINTERVAL`, `ATH_LONG_CALINTERVAL`,
/// `ATH_RESTART_CALINTERVAL` (ms) and `AR9002_CAL_MAX_TIME`.
const SHORT_MS: u64 = 1000;
const LONG_MS: u64 = 30_000;
const RESTART_MS: u64 = 1_200_000;
const CAL_MAX_MS: u64 = 30_000;
/// `ATH9K_NF_CAL_HIST_MAX` / `AR_PHY_CCA_FILTERWINDOW_LENGTH`.
const HIST: usize = 5;
const FILTER_WINDOW: u8 = 5;
const AGC: u64 = 0x9860;
const AGC_NF: u32 = 0x2;
const AGC_ENABLE_NF: u32 = 0x8000;
const AGC_NO_UPDATE_NF: u32 = 0x20000;
/// `AR_PHY_TIMING_CTRL4(0)` `DO_CAL`.
const DO_CAL: u32 = 0x10000;

pub(in crate::ath9k) use super::ar9287::CalState;

/// One `ath_ani_calibrate` outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Tick {
    pub longcal: bool,
    pub shortcal: bool,
    /// `chan->noisefloor` after a completed `ath9k_hw_getnf`.
    pub noise_floor: Option<i16>,
    /// AR9160 per-chain coefficients written by `ar9002_hw_iqcalibrate`
    /// after the 64th sample.
    pub iq: Option<[Option<(u8, i8)>; CHAINS]>,
}

/// AR9160 `iq_caldata` list entry: `calState`, `CalValid`, the start time
/// and the `cal_samples`/totals of `iq_cal_multi_sample`.
#[derive(Clone, Copy, Debug)]
struct IqCal {
    state: CalState,
    valid: bool,
    start_ms: u64,
    samples: u32,
    totals: IqTotals,
}

/// Periodic calibration of one AR5416/AR9160 generation: the `ath_common`
/// ANI timers and `caldone`, the three-chain `ath9k_hw_cal_data` NF
/// history, `NFCAL_PENDING`/`LONGCAL_PENDING` and, on AR9160 only, the
/// multi-sample IQ list entry. ANI is not part of this owner.
#[derive(Clone, Debug)]
pub(in crate::ath9k) struct Periodic {
    rx_chainmask: u8,
    limits: Limits,
    hist: [[i16; HIST]; CHAINS],
    index: [usize; CHAINS],
    priv_nf: [i16; CHAINS],
    invalid: [u8; CHAINS],
    nfcal_pending: bool,
    longcal_pending: bool,
    iq: Option<IqCal>,
    caldone: bool,
    longcal_ms: u64,
    shortcal_ms: u64,
    resetcal_ms: u64,
}
impl Periodic {
    /// State after [`Calibration::run`] at `now_ms` (`ath_start_ani`):
    /// `ath9k_init_nfcal_hist_buffer` at the band's nominal NF, the init NF
    /// calibration pending its `ath9k_hw_getnf`, and on AR9160 the IQ
    /// calibration that run completed (`CalValid`).
    pub(in crate::ath9k) fn new(report: &Report, now_ms: u64) -> Self {
        let limits = limits_for(report.five_ghz);
        Self {
            rx_chainmask: report.rx_chainmask,
            limits,
            hist: [[limits.nominal; HIST]; CHAINS],
            index: [0; CHAINS],
            priv_nf: [limits.nominal; CHAINS],
            invalid: [FILTER_WINDOW; CHAINS],
            nfcal_pending: true,
            longcal_pending: false,
            iq: has_iq(report.chip).then_some(IqCal {
                state: CalState::Done,
                valid: true,
                start_ms: now_ms,
                samples: 0,
                totals: IqTotals::default(),
            }),
            caldone: false,
            longcal_ms: now_ms,
            shortcal_ms: now_ms,
            resetcal_ms: 0,
        }
    }
    pub(in crate::ath9k) fn caldone(&self) -> bool {
        self.caldone
    }
    pub(in crate::ath9k) fn iq_state(&self) -> Option<CalState> {
        self.iq.map(|iq| iq.state)
    }
    pub(in crate::ath9k) fn iq_samples(&self) -> Option<u32> {
        self.iq.map(|iq| iq.samples)
    }
    pub(in crate::ath9k) fn private_nf(&self) -> [i16; CHAINS] {
        self.priv_nf
    }

    /// `link.c::ath_ani_calibrate` without ANI (see the AR9287 owner). An
    /// `Err` is `ath9k_queue_reset(RESET_TYPE_CALIBRATION)`.
    pub(in crate::ath9k) fn tick(
        &mut self,
        io: &mut impl RegisterIo,
        now_ms: u64,
    ) -> Result<Tick, BringUpError> {
        let mut tick = Tick::default();
        if now_ms.wrapping_sub(self.longcal_ms) >= LONG_MS {
            tick.longcal = true;
            self.longcal_ms = now_ms;
        }
        if !self.caldone {
            if now_ms.wrapping_sub(self.shortcal_ms) >= SHORT_MS {
                tick.shortcal = true;
                self.shortcal_ms = now_ms;
                self.resetcal_ms = now_ms;
            }
        } else if now_ms.wrapping_sub(self.resetcal_ms) >= RESTART_MS {
            self.caldone = self.reset_calvalid();
            if self.caldone {
                self.resetcal_ms = now_ms;
            }
        }
        if tick.longcal || tick.shortcal {
            match self.calibrate(io, tick.longcal, now_ms, &mut tick) {
                Ok(done) => self.caldone = done,
                Err(error) => {
                    self.caldone = false;
                    return Err(error);
                }
            }
        }
        Ok(tick)
    }

    /// `ath9k_hw_reset_calvalid`: below AR9160 (no list) it returns true.
    fn reset_calvalid(&mut self) -> bool {
        let Some(iq) = self.iq.as_mut() else {
            return true;
        };
        if iq.state != CalState::Done {
            return true;
        }
        iq.valid = false;
        iq.state = CalState::Waiting;
        false
    }

    /// `ar9002_hw_calibrate` (20 MHz; no PA calibration, no OLC step).
    fn calibrate(
        &mut self,
        io: &mut impl RegisterIo,
        mut longcal: bool,
        now_ms: u64,
        tick: &mut Tick,
    ) -> Result<bool, BringUpError> {
        let nfcal = read(io, AGC)? & AGC_NF != 0;
        let nfcal_pending = self.nfcal_pending;
        if longcal {
            self.longcal_pending = true;
        } else if self.longcal_pending {
            longcal = true;
        }
        let state = self.iq.map(|iq| iq.state);
        let mut percal_pending = matches!(state, Some(CalState::Running | CalState::Waiting));
        if percal_pending && !nfcal {
            if !self.per_calibration(io, now_ms, tick)? {
                return Ok(false);
            }
            percal_pending = self.iq.is_some_and(|iq| iq.state == CalState::Waiting);
        }
        if percal_pending && !nfcal && !longcal {
            self.reset_calibration(io, now_ms)?;
            return Ok(false);
        }
        if longcal || nfcal_pending {
            if self.getnf(io, tick)? {
                self.loadnf(io)?;
            }
            if longcal {
                self.longcal_pending = false;
                self.start_nfcal(io)?;
            }
        }
        Ok(!percal_pending)
    }

    /// `ar9002_hw_per_calibration` for `iq_cal_multi_sample`.
    fn per_calibration(
        &mut self,
        io: &mut impl RegisterIo,
        now_ms: u64,
        tick: &mut Tick,
    ) -> Result<bool, BringUpError> {
        let Some(mut iq) = self.iq else {
            return Ok(false);
        };
        let done = match iq.state {
            CalState::Running => {
                if read(io, 0x9920)? & DO_CAL == 0 {
                    collect(io, &mut iq.totals)?;
                    iq.samples += 1;
                    if iq.samples >= MAX_CAL_SAMPLES {
                        tick.iq = Some(iqcalibrate(io, self.rx_chainmask, &iq.totals)?);
                        iq.valid = true;
                        iq.state = CalState::Done;
                        true
                    } else {
                        setup_iq(io)?;
                        false
                    }
                } else if now_ms.wrapping_sub(iq.start_ms) > CAL_MAX_MS {
                    modify(io, 0x9920, DO_CAL, 0)?;
                    iq.state = CalState::Waiting;
                    true
                } else {
                    false
                }
            }
            _ if !iq.valid => {
                self.iq = Some(iq);
                self.reset_calibration(io, now_ms)?;
                return Ok(false);
            }
            _ => false,
        };
        self.iq = Some(iq);
        Ok(done)
    }

    /// `ath9k_hw_reset_calibration`: setup, start time, CAL_RUNNING, totals
    /// and `cal_samples` zeroed.
    fn reset_calibration(
        &mut self,
        io: &mut impl RegisterIo,
        now_ms: u64,
    ) -> Result<(), BringUpError> {
        let Some(iq) = self.iq.as_mut() else {
            return Ok(());
        };
        setup_iq(io)?;
        iq.start_ms = now_ms;
        iq.state = CalState::Running;
        iq.totals = IqTotals::default();
        iq.samples = 0;
        Ok(())
    }

    /// `calib.c::ath9k_hw_getnf` with `ar5008_hw_do_getnf` (all three
    /// control chains read and sanitized) and
    /// `ath9k_hw_update_nfcal_hist_buffer` for the receiving chains.
    fn getnf(&mut self, io: &mut impl RegisterIo, tick: &mut Tick) -> Result<bool, BringUpError> {
        if read(io, AGC)? & AGC_NF != 0 {
            return Ok(false);
        }
        let mut nf = [0i16; CHAINS];
        for (chain, value) in nf.iter_mut().enumerate() {
            let raw = minimum_cca(io, chain)?;
            *value = if raw == 0 {
                0
            } else {
                self.limits.sanitize(raw)
            };
        }
        self.nfcal_pending = false;
        for (chain, &value) in nf.iter().enumerate() {
            if self.rx_chainmask & (1 << chain) == 0 {
                continue;
            }
            self.hist[chain][self.index[chain]] = value;
            self.index[chain] = (self.index[chain] + 1) % HIST;
            if self.invalid[chain] > 0 {
                self.invalid[chain] -= 1;
                self.priv_nf[chain] = value;
            } else {
                let mut sorted = self.hist[chain];
                sorted.sort_unstable_by(|a, b| b.cmp(a));
                self.priv_nf[chain] = sorted[(HIST - 1) >> 1];
            }
            if self.priv_nf[chain] != 0 && self.priv_nf[chain] > self.limits.max {
                self.priv_nf[chain] = self.limits.max;
            }
        }
        tick.noise_floor = Some(self.priv_nf[0]);
        Ok(true)
    }

    /// `calib.c::ath9k_hw_loadnf` with the history `privNF` per receiving
    /// control chain; a 22.2 ms load timeout is `-ETIMEDOUT`.
    fn loadnf(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        let agc = read(io, AGC)?;
        for (chain, register) in NF_REGS.iter().enumerate() {
            if self.rx_chainmask & (1 << chain) != 0 {
                modify(io, *register, 0x1ff, nf_field(self.priv_nf[chain]))?;
            }
        }
        if agc & AGC_NF != 0 {
            modify(io, AGC, AGC_NF, 0)?;
        }
        modify(io, AGC, AGC_ENABLE_NF, 0)?;
        modify(io, AGC, AGC_NO_UPDATE_NF, 0)?;
        modify(io, AGC, 0, AGC_NF)?;
        let mut loaded = false;
        for _ in 0..22_200 {
            if read(io, AGC)? & AGC_NF == 0 {
                loaded = true;
                break;
            }
            io.delay_us(10);
        }
        if agc & AGC_NF != 0 {
            if agc & AGC_ENABLE_NF != 0 {
                modify(io, AGC, 0, AGC_ENABLE_NF)?;
            }
            if agc & AGC_NO_UPDATE_NF != 0 {
                modify(io, AGC, 0, AGC_NO_UPDATE_NF)?;
            }
            modify(io, AGC, 0, AGC_NF)?;
        }
        if !loaded {
            return Err(BringUpError::Timeout);
        }
        for (chain, register) in NF_REGS.iter().enumerate() {
            if self.rx_chainmask & (1 << chain) != 0 {
                modify(io, *register, 0x1ff, nf_field(-50))?;
            }
        }
        Ok(())
    }

    /// `calib.c::ath9k_hw_start_nfcal(ah, false)`.
    fn start_nfcal(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        self.nfcal_pending = true;
        modify(io, AGC, 0, AGC_ENABLE_NF)?;
        modify(io, AGC, 0, AGC_NO_UPDATE_NF)?;
        modify(io, AGC, 0, AGC_NF)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
