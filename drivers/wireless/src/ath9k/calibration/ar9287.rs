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
/// `ath_nf_limits` (`ar9002_phy.c::ar9002_hw_set_nf_limits`); the def and
/// AR9287 maps carry no `nf_2g.cal`/`nf_5g.cal`, so `nominal` is also the
/// default NF (`calib.c::ath9k_hw_get_default_nf`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Limits {
    pub nominal: i16,
    pub min: i16,
    pub max: i16,
}
impl Limits {
    /// `ath9k_hw_nf_sanitize` for one reading.
    pub(super) fn sanitize(self, raw: i16) -> i16 {
        if raw > self.max {
            self.max
        } else if raw < self.min {
            self.nominal
        } else {
            raw
        }
    }
}
/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_9287_2GHZ`.
pub(in crate::ath9k) const LIMITS: Limits = Limits {
    nominal: -112,
    min: -127,
    max: -97,
};
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
        agc(io, false).await?;
        let (measured_noise_dbm, noise_dbm) = noise(io, rx_chainmask, LIMITS).await?;
        let iq = iq(io, rx_chainmask, VERSION).await?;
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

/// `ar9002_hw_init_cal` for AR_SREV_9280_20_OR_LATER: `FLTR_CAL` brackets
/// the AGC offset calibration, polled for `AH_WAIT_TIMEOUT`. Below
/// AR9287 1.1 (`pwdadc`, i.e. AR9280) `AR_PHY_ADC_CTL_OFF_PWDADC` is cleared
/// before and set again after it.
pub(super) async fn agc(io: &mut impl Io, pwdadc: bool) -> Result<(), BringUpError> {
    if pwdadc {
        modify(io, 0x982c, 0x8000, 0)?;
    }
    modify(io, 0x9860, 0, 0x10000)?;
    modify(io, 0x9860, 0, 1)?;
    wait(io, 0x9860, 1, 100_000).await?;
    if pwdadc {
        modify(io, 0x982c, 0, 0x8000)?;
    }
    modify(io, 0x9860, 0x10000, 0)
}

fn nf_field(value: i16) -> u32 {
    ((value as u32) << 1) & 0x1ff
}

/// `ath9k_hw_loadnf` (history at its `nominal` initial value), the -50
/// maxCCA restore, `ath9k_hw_start_nfcal(update)`, then the completed
/// `ar9002_hw_do_getnf` readings with `ath9k_hw_nf_sanitize`.
pub(super) async fn noise(
    io: &mut impl Io,
    rx_chainmask: u8,
    limits: Limits,
) -> Result<([Option<i16>; 2], [Option<i16>; 2]), BringUpError> {
    let chains = || (0..2usize).filter(move |c| rx_chainmask & (1 << *c) != 0);
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
        applied[chain] = Some(limits.sanitize(raw));
    }
    Ok((measured, applied))
}

/// `iq_cal_single_sample`: `ar9002_hw_setup_calibration` (log count
/// `PER_MAX_LOG_COUNT`, `AR_PHY_CALMODE_IQ`, `DO_CAL`), one collected sample,
/// then `ar9002_hw_iqcalibrate` over chains `0..numChains` and the chain-0
/// `IQCORR_ENABLE`.
pub(super) async fn iq(
    io: &mut impl Io,
    rx_chainmask: u8,
    version: u32,
) -> Result<[Option<(u8, i8)>; 2], BringUpError> {
    field(io, 0x9920, 0xf000, 12, 10)?;
    write(io, 0x99f0, 0)?;
    modify(io, 0x9920, 0, 0x10000)?;
    wait(io, 0x9920, 0x10000, 30_000_000).await?;
    let chains = rx_chainmask.count_ones() as usize;
    let mut measured = [(0u32, 0u32, 0u32); 2];
    for (chain, slot) in measured.iter_mut().enumerate().take(chains) {
        let at = chain as u64 * CHAIN;
        *slot = (
            measurement_for(io, 0x9c10 + at, version)?,
            measurement_for(io, 0x9c14 + at, version)?,
            measurement_for(io, 0x9c18 + at, version)?,
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

/// `ath9k.h` `ATH_STA_SHORT_CALINTERVAL`, `ATH_LONG_CALINTERVAL` and
/// `ATH_RESTART_CALINTERVAL` (ms); `ar9002_calib.c::AR9002_CAL_MAX_TIME`.
const SHORT_MS: u64 = 1000;
const LONG_MS: u64 = 30_000;
const RESTART_MS: u64 = 1_200_000;
const CAL_MAX_MS: u64 = 30_000;
/// `calib.h` `ATH9K_NF_CAL_HIST_MAX` / `AR_PHY_CCA_FILTERWINDOW_LENGTH`.
const HIST: usize = 5;
const FILTER_WINDOW: u8 = 5;
/// `AR_PHY_AGC_CONTROL` and its `NF`, `ENABLE_NF`, `NO_UPDATE_NF` bits.
const AGC: u64 = 0x9860;
const AGC_NF: u32 = 0x2;
const AGC_ENABLE_NF: u32 = 0x8000;
const AGC_NO_UPDATE_NF: u32 = 0x20000;
/// `AR_PHY_TIMING_CTRL4(0)` `DO_CAL`.
const DO_CAL: u32 = 0x10000;

/// `ath9k_cal_list::calState` of the single AR9287 20 MHz per-calibration
/// (`iq_cal_single_sample`; ADC DC is HT40-only, ADC gain unsupported).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum CalState {
    Waiting,
    Running,
    Done,
}

/// One `ath_ani_calibrate` outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Tick {
    pub longcal: bool,
    pub shortcal: bool,
    /// `chan->noisefloor` after a completed `ath9k_hw_getnf`.
    pub noise_floor: Option<i16>,
    /// New per-chain IQ coefficients written by `ar9002_hw_iqcalibrate`.
    pub iq: Option<[Option<(u8, i8)>; 2]>,
    /// `ar9287_hw_olc_temp_compensation` delta on a long calibration.
    pub temp_delta: Option<i32>,
}

/// Periodic calibration state of one AR9287 generation: the `ath_common`
/// ANI timers and `caldone`, the `ath9k_hw_cal_data` NF history,
/// `CalValid` and `NFCAL_PENDING`/`LONGCAL_PENDING` flags, and the IQ
/// per-calibration list entry. ANI itself is not part of this owner.
#[derive(Clone, Debug)]
pub(in crate::ath9k) struct Periodic {
    rx_chainmask: u8,
    /// `ah->initPDADC` for `ar9287_hw_olc_temp_compensation`, or `None` for
    /// a closed-loop map (`OLC_FOR_AR9280_20_LATER` false: no step runs).
    init_pdadc: Option<u8>,
    limits: Limits,
    version: u32,
    hist: [[i16; HIST]; 2],
    index: [usize; 2],
    priv_nf: [i16; 2],
    invalid: [u8; 2],
    nfcal_pending: bool,
    longcal_pending: bool,
    iq: CalState,
    iq_valid: bool,
    iq_start_ms: u64,
    caldone: bool,
    longcal_ms: u64,
    shortcal_ms: u64,
    resetcal_ms: u64,
}
impl Periodic {
    /// State after `calibration::ar9287::Calibration::run` at `now_ms`
    /// (`ath_start_ani` timers): `ath9k_init_nfcal_hist_buffer` at the
    /// nominal NF (AR9287 has no `nf_2g.cal`), the init NF calibration
    /// still pending its `ath9k_hw_getnf`, and the IQ calibration that run
    /// completed (`CalValid`).
    pub(in crate::ath9k) fn new(report: &Report, now_ms: u64) -> Self {
        Self::with(
            report.rx_chainmask,
            Some(report.init_pdadc),
            LIMITS,
            VERSION,
            now_ms,
        )
    }
    /// The same initial state for another AR9002 chip's limits and
    /// `AR_SREV` version (`super::ar9280::Periodic`).
    pub(super) fn with(
        rx_chainmask: u8,
        init_pdadc: Option<u8>,
        limits: Limits,
        version: u32,
        now_ms: u64,
    ) -> Self {
        Self {
            rx_chainmask,
            init_pdadc,
            limits,
            version,
            hist: [[limits.nominal; HIST]; 2],
            index: [0; 2],
            priv_nf: [limits.nominal; 2],
            invalid: [FILTER_WINDOW; 2],
            nfcal_pending: true,
            longcal_pending: false,
            iq: CalState::Done,
            iq_valid: true,
            iq_start_ms: now_ms,
            caldone: false,
            longcal_ms: now_ms,
            shortcal_ms: now_ms,
            resetcal_ms: 0,
        }
    }
    pub(in crate::ath9k) fn caldone(&self) -> bool {
        self.caldone
    }
    pub(in crate::ath9k) fn iq_state(&self) -> CalState {
        self.iq
    }
    pub(in crate::ath9k) fn private_nf(&self) -> [i16; 2] {
        self.priv_nf
    }

    /// `link.c::ath_ani_calibrate` without ANI: long calibration every 30 s,
    /// short calibrations every second while not `caldone`, and the 20 min
    /// `ath9k_hw_reset_calvalid` restart. An `Err` is Linux's
    /// `ath9k_queue_reset(RESET_TYPE_CALIBRATION)`: the caller must close
    /// this generation.
    pub(in crate::ath9k) fn tick(
        &mut self,
        io: &mut impl RegisterIo,
        image: &[u8],
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
            match self.calibrate(io, image, tick.longcal, now_ms, &mut tick) {
                Ok(done) => self.caldone = done,
                Err(error) => {
                    self.caldone = false;
                    return Err(error);
                }
            }
        }
        Ok(tick)
    }

    /// `calib.c::ath9k_hw_reset_calvalid` for the one-entry list.
    fn reset_calvalid(&mut self) -> bool {
        if self.iq != CalState::Done {
            return true;
        }
        self.iq_valid = false;
        self.iq = CalState::Waiting;
        false
    }

    /// `ar9002_calib.c::ar9002_hw_calibrate` (20 MHz, no PA calibration on
    /// AR9287); returns `!percal_pending`.
    fn calibrate(
        &mut self,
        io: &mut impl RegisterIo,
        image: &[u8],
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
        let mut percal_pending = matches!(self.iq, CalState::Running | CalState::Waiting);
        if percal_pending && !nfcal {
            if !self.per_calibration(io, now_ms, tick)? {
                return Ok(false);
            }
            // The single-entry list has no other waiting calibration.
            percal_pending = self.iq == CalState::Waiting;
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
                if let Some(init_pdadc) = self.init_pdadc {
                    tick.temp_delta = olc_temp_compensation(io, image, init_pdadc)?;
                }
            }
        }
        Ok(!percal_pending)
    }

    /// `ar9002_hw_per_calibration` for `iq_cal_single_sample`.
    fn per_calibration(
        &mut self,
        io: &mut impl RegisterIo,
        now_ms: u64,
        tick: &mut Tick,
    ) -> Result<bool, BringUpError> {
        match self.iq {
            CalState::Running => {
                if read(io, 0x9920)? & DO_CAL == 0 {
                    // MIN_CAL_SAMPLES (1): collect, then post-process.
                    tick.iq = Some(self.iqcalibrate(io)?);
                    self.iq_valid = true;
                    self.iq = CalState::Done;
                    Ok(true)
                } else if now_ms.wrapping_sub(self.iq_start_ms) > CAL_MAX_MS {
                    modify(io, 0x9920, DO_CAL, 0)?;
                    self.iq = CalState::Waiting;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ if !self.iq_valid => {
                self.reset_calibration(io, now_ms)?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// `ath9k_hw_reset_calibration` → `ar9002_hw_setup_calibration`
    /// (`PER_MAX_LOG_COUNT`, `AR_PHY_CALMODE_IQ`, `DO_CAL`).
    fn reset_calibration(
        &mut self,
        io: &mut impl RegisterIo,
        now_ms: u64,
    ) -> Result<(), BringUpError> {
        field(io, 0x9920, 0xf000, 12, 10)?;
        write(io, 0x99f0, 0)?;
        modify(io, 0x9920, 0, DO_CAL)?;
        self.iq_start_ms = now_ms;
        self.iq = CalState::Running;
        Ok(())
    }

    /// `ar9002_hw_iqcal_collect` (one sample) and `ar9002_hw_iqcalibrate`
    /// over `numChains`: a chain whose denominators are zero keeps its
    /// coefficients, then chain 0 `IQCORR_ENABLE` is set.
    fn iqcalibrate(
        &mut self,
        io: &mut impl RegisterIo,
    ) -> Result<[Option<(u8, i8)>; 2], BringUpError> {
        let chains = self.rx_chainmask.count_ones() as usize;
        let mut out = [None; 2];
        for (chain, slot) in out.iter_mut().enumerate().take(chains) {
            let at = chain as u64 * CHAIN;
            let i = measurement_for(io, 0x9c10 + at, self.version)?;
            let q = measurement_for(io, 0x9c14 + at, self.version)?;
            let correlation = measurement_for(io, 0x9c18 + at, self.version)?;
            *slot = iq_coefficients(i, q, correlation).ok();
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

    /// `calib.c::ath9k_hw_getnf`: `ar9002_hw_do_getnf` for the receiving
    /// control chains, `ath9k_hw_nf_sanitize`, and
    /// `ath9k_hw_update_nfcal_hist_buffer`.
    fn getnf(&mut self, io: &mut impl RegisterIo, tick: &mut Tick) -> Result<bool, BringUpError> {
        if read(io, AGC)? & AGC_NF != 0 {
            return Ok(false);
        }
        let mut nf = [0i16; 2];
        for (chain, value) in nf.iter_mut().enumerate() {
            if chain == 1 && self.rx_chainmask & 2 == 0 {
                break;
            }
            let raw = ((read(io, NF_REGS[chain])? >> 20) & 0x1ff) as i16;
            let raw = (raw << 7) >> 7;
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
                // ath9k_hw_get_nf_hist_mid: reverse sort, element 2.
                let mut sorted = self.hist[chain];
                sorted.sort_unstable_by(|a, b| b.cmp(a));
                self.priv_nf[chain] = sorted[(HIST - 1) >> 1];
            }
            // NFCAL_INTF is never set (no beacon-stuck path on a station).
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
