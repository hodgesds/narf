// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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
//! AR9300 initial and periodic calibration of one full-reset 20 MHz
//! channel: `ar9003_phy.c::ar9003_hw_init_bb`, the PCOEM
//! `ar9003_calib.c::ar9003_hw_init_cal_pcoem` (AR9300 has neither
//! `ATH9K_HW_CAP_RTT` nor MCI, and `TX_IQ_ON_AGC_CAL` is
//! `AR_SREV_9485_OR_LATER`), the `ath9k_hw_reset` tail's
//! `ath9k_hw_loadnf` + `ath9k_hw_start_nfcal(ah, true)`, and the periodic
//! `ar9003_hw_calibrate` driven by `link.c::ath_ani_calibrate` (ANI is not
//! part of this owner), with the AR9300 `ar9003_hw_set_nf_limits` limits
//! and the `ar9300_cca_regs` control-chain NF registers. On MCI parts
//! the MCI calibration handshake (`mci::init_cal_req` / `init_cal_done`,
//! `mci::start_reset` / `end_reset`) wraps this calibration when the
//! link is enabled; the handshake lives in `mci`, not here.
//!
//! TX IQ calibration as Linux runs it on AR9300: `ar9003_hw_init_cal_settings`
//! enables `TX_IQ_CAL`, so `init_cal_pcoem` programs the
//! `AR_PHY_TX_IQCAL_CONTROL_1` `DELPT` field; without `TX_IQ_ON_AGC_CAL`
//! `txiqcal_done` stays false, `ath9k_hw_reset` cleared `TXIQCAL_DONE`, and
//! neither `ar9003_hw_tx_iq_cal_post_proc` nor `_reload` runs. The
//! carrier-leak table copy into `caldata->tx_clcal` is not kept:
//! `ath9k_hw_reset` clears `TXCLCAL_DONE` before every full-reset
//! `init_cal`, so only the (unported) fast channel change would reload it.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{eeprom::Identity, field, phy::Prepared, rmw};
use crate::ath9k::{
    calibration::{ar9287::Limits, Io},
    identity::{BringUpError, RegisterIo},
};

/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_9300_2GHZ`.
pub(in crate::ath9k) const LIMITS_2GHZ: Limits = Limits {
    nominal: -110,
    min: -125,
    max: -60,
};
/// `AR_PHY_CCA_{NOM,MIN_GOOD,MAX_GOOD}_VAL_9300_5GHZ`.
pub(in crate::ath9k) const LIMITS_5GHZ: Limits = Limits {
    nominal: -115,
    min: -125,
    max: -60,
};

const AR_CR: u64 = 0x0008;
const AR_CR_RXE: u32 = 0xc;
const AR_IER: u64 = 0x0024;
const AR_Q_TXE: u64 = 0x0840;
const AR_DIAG_SW: u64 = 0x8048;
const AR_DIAG_RX_PARK: u32 = 0x0200_0020;
const AR_SELFGEN_MASK: u64 = 0x832c;
const AR_PHY_TIMING4: u64 = 0x980c;
const AR_PHY_TIMING4_IQCAL_LOG_COUNT_MAX: u32 = 0xf000;
const AR_PHY_TIMING4_DO_CAL: u32 = 0x10000;
const AR_PHY_ACTIVE: u64 = 0xa20c;
const AR_PHY_RX_DELAY: u64 = 0xa254;
const AR_PHY_RX_DELAY_DELAY: u32 = 0x3fff;
const AR_PHY_RX_CHAINMASK: u64 = 0xa2a0;
const AR_PHY_CAL_CHAINMASK: u64 = 0xa2c0;
const AR_PHY_AGC_CONTROL: u64 = 0xa2c4;
const AGC_CAL: u32 = 0x1;
const AGC_NF: u32 = 0x2;
const AGC_ENABLE_NF: u32 = 0x8000;
const AGC_NO_UPDATE_NF: u32 = 0x20000;
const AGC_CLC_SUCCESS: u32 = 0x80000;
const AR_PHY_CALMODE: u64 = 0xa2c8;
const AR_PHY_CALMODE_IQ: u32 = 0;
const AR_PHY_CL_CAL_CTL: u64 = 0xa2d8;
const AR_PHY_CL_CAL_ENABLE: u32 = 0x2;
const AR_PHY_ANALOG_SWAP: u64 = 0xa34c;
const AR_PHY_SWAP_ALT_CHAIN: u32 = 0x40;
const AR_PHY_TX_IQCAL_CONTROL_1: u64 = 0xa648;
const DELPT_MASK: u32 = 0x01fc_0000;
const DELPT_SHIFT: u32 = 18;
/// `ar9003_calib.c` `DELPT`.
const DELPT: u32 = 32;
/// `AR_PHY_CAL_MEAS_{0,1,2}(chain)`.
const CAL_MEAS: [u64; 3] = [0x98c0, 0xa8c0, 0xb8c0];
/// `AR_PHY_RX_IQCAL_CORR_B{0,1,2}` and its fields.
const RX_IQCAL_CORR: [u64; 3] = [0x98dc, 0xa8dc, 0xb8dc];
const IQCORR_Q_I_COFF: u32 = 0x3f80;
const IQCORR_Q_Q_COFF: u32 = 0x7f;
const IQCORR_ENABLE: u32 = 0x4000;
/// `ar9300_cca_regs[0..3]`: `AR_PHY_CCA_0/1/2` (control chains; the
/// extension-channel registers are HT40-only).
const NF_REGS: [u64; 3] = [0x9e1c, 0xae1c, 0xbe1c];
/// `AR_PHY_65NM_RXRF_GAINSTAGES(chain)`, `_RXTX2(chain)`, `_RXRF_AGC(chain)`.
const GAINSTAGES: [u64; 3] = [0x16008, 0x16408, 0x16808];
const RXTX2: [u64; 3] = [0x16104, 0x16504, 0x16904];
const RXRF_AGC: [u64; 3] = [0x1600c, 0x1640c, 0x1680c];
/// `hw.h` `AH_WAIT_TIMEOUT` (µs) and `BASE_ACTIVATE_DELAY`.
const AH_WAIT_TIMEOUT: u64 = 100_000;
const BASE_ACTIVATE_DELAY: u64 = 100;
/// `calib.h` `PER_MAX_LOG_COUNT`, `MIN_CAL_SAMPLES`.
const PER_MAX_LOG_COUNT: u32 = 10;
const MIN_CAL_SAMPLES: u8 = 1;
/// `ath9k.h` `ATH_STA_SHORT_CALINTERVAL`, `ATH_LONG_CALINTERVAL`,
/// `ATH_RESTART_CALINTERVAL` (ms).
const SHORT_MS: u64 = 1000;
const LONG_MS: u64 = 30_000;
const RESTART_MS: u64 = 1_200_000;
/// `calib.h` `ATH9K_NF_CAL_HIST_MAX` / `AR_PHY_CCA_FILTERWINDOW_LENGTH`.
const HIST: usize = 5;
const FILTER_WINDOW: u8 = 5;

fn read(io: &mut impl RegisterIo, register: u64) -> Result<u32, BringUpError> {
    let value = io.read32(register);
    if value == u32::MAX || !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(value)
}

fn write(io: &mut impl RegisterIo, register: u64, value: u32) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(register, value);
    Ok(())
}

fn chains(mask: u8) -> impl Iterator<Item = usize> {
    (0..3usize).filter(move |c| mask & (1 << c) != 0)
}

/// `ar9003_hw_set_nf_limits` for the band.
pub(in crate::ath9k) fn limits(five_ghz: bool) -> Limits {
    if five_ghz {
        LIMITS_5GHZ
    } else {
        LIMITS_2GHZ
    }
}

/// `ar9003_hw_set_chain_masks`: the alternate-chain swap follows the chip
/// (`caps`) masks; `selfgen` is the `ATH9K_HW_CAP_APM`-reduced TX mask the
/// prepared channel computed.
fn set_chain_masks(
    io: &mut impl RegisterIo,
    identity: &Identity,
    rx: u8,
    selfgen: u8,
) -> Result<(), BringUpError> {
    if identity.tx_chainmask == 5 || identity.rx_chainmask == 5 {
        rmw(io, AR_PHY_ANALOG_SWAP, 0, AR_PHY_SWAP_ALT_CHAIN)?;
    }
    write(io, AR_PHY_RX_CHAINMASK, u32::from(rx))?;
    write(io, AR_PHY_CAL_CHAINMASK, u32::from(rx))?;
    write(io, AR_SELFGEN_MASK, u32::from(selfgen))
}

/// `ath9k_hw_wait(AR_PHY_AGC_CONTROL, mask, 0, AH_WAIT_TIMEOUT)`.
async fn wait_clear(io: &mut impl Io, mask: u32, timeout: u64) -> Result<bool, BringUpError> {
    let start = io.now_us();
    loop {
        if read(io, AR_PHY_AGC_CONTROL)? & mask == 0 {
            return Ok(true);
        }
        if io.now_us().saturating_sub(start) >= timeout {
            return Ok(false);
        }
        io.settle(10).await;
    }
}

/// `ar9003_hw_manual_peak_cal` for one chain on an `AR_SREV_9003_PCOEM`
/// part (peak-detect threshold 0); returns the CALDAC the binary search
/// settled on.
fn manual_peak_cal(
    io: &mut impl RegisterIo,
    chain: usize,
    two_ghz: bool,
) -> Result<u8, BringUpError> {
    let (gain, rxtx2, agc) = (GAINSTAGES[chain], RXTX2[chain], RXRF_AGC[chain]);
    // Turn off LNA/SW (RX_OVERRIDE, LNAON_CALDC, the band LNA gain override).
    field(io, gain, 0x8000_0000, 31, 1)?;
    field(io, gain, 0x2, 1, 0)?;
    if two_ghz {
        field(io, gain, 0x7000_0000, 28, 0)?;
    } else {
        field(io, gain, 0x0380_0000, 23, 0)?;
    }
    // Turn off RXON.
    field(io, rxtx2, 0x1000, 12, 1)?;
    field(io, rxtx2, 0x800, 11, 0)?;
    // Turn on AGC for cal.
    field(io, agc, 0x8000_0000, 31, 1)?;
    field(io, agc, 0x4000_0000, 30, 1)?;
    field(io, agc, 0x2000_0000, 29, 1)?;
    let (caldac_mask, caldac_shift) = if two_ghz {
        field(io, agc, 0x1e00_0000, 25, 0)?;
        (0x01f8_0000, 19)
    } else {
        field(io, agc, 0x0007_8000, 15, 0)?;
        (0x7e00, 9)
    };
    let mut total = 0u32;
    for i in (1..=6u32).rev() {
        let test = total + (1 << (i - 1));
        field(io, agc, caldac_mask, caldac_shift, test)?;
        io.delay_us(100);
        let agc_out = (read(io, agc)? & 0x4) >> 2;
        total += u32::from(agc_out == 0) << (i - 1);
    }
    field(io, agc, caldac_mask, caldac_shift, total)?;
    // Turn on LNA, release RXON, end the peak-detect calibration.
    field(io, gain, 0x8000_0000, 31, 0)?;
    field(io, rxtx2, 0x1000, 12, 0)?;
    field(io, agc, 0x2000_0000, 29, 0)?;
    Ok(total as u8)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Running,
    Ready,
    Failed,
}

struct Attempt<'a> {
    state: &'a mut State,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        // Cancellation or an error leaves a radio only a new complete reset
        // may reuse; no MMIO cleanup is attempted here.
        if *self.state == State::Running {
            *self.state = State::Failed;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub frequency_mhz: u16,
    pub five_ghz: bool,
    pub rx_chainmask: u8,
    pub tx_chainmask: u8,
    /// `ar9003_hw_manual_peak_cal` CALDAC per receiving chain.
    pub peak_caldac: [Option<u8>; 3],
    /// `TX_CL_CAL` (INI `AR_PHY_CL_CAL_ENABLE`): `None` when not enabled,
    /// else `AR_PHY_AGC_CONTROL_CLC_SUCCESS` after the AGC calibration.
    pub carrier_leak: Option<bool>,
    /// `ath9k_hw_get_default_nf` per control chain.
    pub default_nf: [i16; 3],
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

    /// `ar9003_hw_init_bb` then `ar9003_hw_init_cal_pcoem` for the channel
    /// `prepared` describes, with runtime chain masks equal to the chip's.
    /// The channel's calibration data is fresh (`TXCLCAL_DONE` and
    /// `TXIQCAL_DONE` clear, as `ath9k_hw_reset` leaves them). The IQ
    /// mismatch calibration is left running (`ar9003_hw_init_cal_common`);
    /// `Periodic::start` performs the reset tail's NF load.
    ///
    /// # Safety
    /// Exclusive identified AR9300 directly after `phy::prepare` for
    /// `prepared`. PCI BME off, no published packet DMA, MAC/TX/IRQ parked.
    /// A new attempt requires an independently proved complete reset.
    pub(in crate::ath9k) async unsafe fn run(
        &mut self,
        io: &mut impl Io,
        identity: &Identity,
        prepared: &Prepared,
    ) -> Result<Report, BringUpError> {
        if self.state != State::New {
            return Err(BringUpError::BadState);
        }
        let (rx, tx) = (identity.rx_chainmask, identity.tx_chainmask);
        if !(1..=7).contains(&rx)
            || !(1..=7).contains(&tx)
            || prepared.power.frequency != prepared.frequency
            || prepared.power.tx_chainmask != tx
        {
            return Err(BringUpError::BadIdentity);
        }
        if read(io, AR_PHY_ACTIVE)? & 1 != 0
            || read(io, AR_CR)? & AR_CR_RXE != 0
            || read(io, AR_Q_TXE)? & 0x3ff != 0
            || read(io, AR_IER)? & 1 != 0
            || read(io, AR_DIAG_SW)? & AR_DIAG_RX_PARK != AR_DIAG_RX_PARK
        {
            return Err(BringUpError::BadState);
        }
        self.state = State::Running;
        let attempt = Attempt {
            state: &mut self.state,
        };
        let five = prepared.frequency >= 4800;
        let limits = limits(five);

        // ar9003_hw_init_bb: activate, then ath9k_hw_synth_delay (full rate).
        let synth = read(io, AR_PHY_RX_DELAY)? & AR_PHY_RX_DELAY_DELAY;
        write(io, AR_PHY_ACTIVE, 1)?;
        io.settle(u64::from(synth / 10) + BASE_ACTIVATE_DELAY).await;

        // Use chip chainmask only for calibration.
        set_chain_masks(io, identity, rx, prepared.selfgen_mask)?;
        if prepared.carrier_leak_cal {
            rmw(io, AR_PHY_CL_CAL_CTL, 0, AR_PHY_CL_CAL_ENABLE)?;
        }
        // TX_IQ_CAL without TX_IQ_ON_AGC_CAL: DELPT only.
        field(
            io,
            AR_PHY_TX_IQCAL_CONTROL_1,
            DELPT_MASK,
            DELPT_SHIFT,
            DELPT,
        )?;
        let clc = read(io, AR_PHY_CL_CAL_CTL)? & AR_PHY_CL_CAL_ENABLE != 0;
        let mut rx_delay = 0;
        if clc {
            rx_delay = read(io, AR_PHY_RX_DELAY)?;
            write(io, AR_PHY_ACTIVE, 0)?;
            io.delay_us(5);
            write(io, AR_PHY_RX_DELAY, AR_PHY_RX_DELAY_DELAY)?;
            write(io, AR_PHY_ACTIVE, 1)?;
        }
        // Full reset (no AH_FASTCC): calibrate the AGC, poll, and run the
        // manual peak calibration whatever the poll returned.
        let agc = read(io, AR_PHY_AGC_CONTROL)?;
        write(io, AR_PHY_AGC_CONTROL, agc | AGC_CAL)?;
        let status = wait_clear(io, AGC_CAL, AH_WAIT_TIMEOUT).await?;
        let mut peak_caldac = [None; 3];
        for chain in chains(rx) {
            peak_caldac[chain] = Some(manual_peak_cal(io, chain, !five)?);
        }
        if read(io, AR_PHY_CL_CAL_CTL)? & AR_PHY_CL_CAL_ENABLE != 0 {
            write(io, AR_PHY_RX_DELAY, rx_delay)?;
            io.delay_us(5);
        }
        if !status {
            // "offset calibration failed to complete": ath9k_hw_reset -EIO.
            return Err(BringUpError::Timeout);
        }
        // ar9003_hw_cl_cal_post_proc's CLC_SUCCESS sample.
        let carrier_leak = if prepared.carrier_leak_cal {
            Some(read(io, AR_PHY_AGC_CONTROL)? & AGC_CLC_SUCCESS != 0)
        } else {
            None
        };
        // Revert chainmask to runtime parameters (the chip's here).
        set_chain_masks(io, identity, rx, prepared.selfgen_mask)?;
        // ar9003_hw_init_cal_common: the IQ list's
        // ath9k_hw_reset_calibration.
        setup_iq(io)?;
        let default_nf = core::array::from_fn(|chain| {
            match prepared.power.nf_cal[chain] {
                0 => limits.nominal,
                // Interpolated from the map's int8 calibration piers.
                cal => cal as i16,
            }
        });
        let report = Report {
            frequency_mhz: prepared.frequency,
            five_ghz: five,
            rx_chainmask: rx,
            tx_chainmask: tx,
            peak_caldac,
            carrier_leak,
            default_nf,
        };
        self.report = Some(report);
        *attempt.state = State::Ready;
        Ok(report)
    }
}

/// `ar9003_hw_setup_calibration(IQ_MISMATCH_CAL)` with
/// `PER_MAX_LOG_COUNT`.
fn setup_iq(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    field(
        io,
        AR_PHY_TIMING4,
        AR_PHY_TIMING4_IQCAL_LOG_COUNT_MAX,
        12,
        PER_MAX_LOG_COUNT,
    )?;
    write(io, AR_PHY_CALMODE, AR_PHY_CALMODE_IQ)?;
    rmw(io, AR_PHY_TIMING4, 0, AR_PHY_TIMING4_DO_CAL)
}

fn nf_field(value: i16) -> u32 {
    ((value as u32) << 1) & 0x1ff
}

/// `ah->totalPowerMeasI/Q` and `totalIqCorrMeas`. Linux never clears them:
/// they accumulate for the `ath_hw` lifetime, so the owner carries them
/// from one generation into the next.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct IqTotals {
    pub power_i: [u32; 3],
    pub power_q: [u32; 3],
    pub correlation: [i32; 3],
}

/// `ath9k_cal_list::calState` of the single AR9300 per-calibration
/// (`iq_cal_single_sample`; `supp_cals` is `IQ_MISMATCH_CAL` only).
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
    /// `(iCoff, qCoff)` 7-bit fields `ar9003_hw_iqcalibrate` wrote per
    /// chain `0..numChains`; `None` where a denominator was zero.
    pub iq: Option<[Option<(u8, u8)>; 3]>,
}

/// Periodic calibration state of one AR9300 generation: the `ath_common`
/// ANI timers and `caldone`, the `ath9k_hw_cal_data` NF history and
/// `CalValid`, the IQ list entry and `ah->cal_samples`.
#[derive(Clone, Debug)]
pub(in crate::ath9k) struct Periodic {
    rx_chainmask: u8,
    tx_chainmask: u8,
    limits: Limits,
    hist: [[i16; HIST]; 3],
    index: [usize; 3],
    priv_nf: [i16; 3],
    invalid: [u8; 3],
    nfcal_pending: bool,
    iq: CalState,
    iq_valid: bool,
    samples: u8,
    totals: IqTotals,
    caldone: bool,
    longcal_ms: u64,
    shortcal_ms: u64,
    resetcal_ms: u64,
}
impl Periodic {
    /// State after `Calibration::run` at `now_ms` (`ath_start_ani`):
    /// `ath9k_init_nfcal_hist_buffer` at `default_nf`, `CalValid` 0 and
    /// the IQ calibration running. Linux seeds the history from the band's
    /// `nf_2g`/`nf_5g.cal` the previous `ath9k_hw_apply_txpower` left;
    /// this owner uses the reset channel's own interpolated value, which
    /// is what Linux holds after any earlier reset onto that channel.
    pub(in crate::ath9k) fn new(report: &Report, totals: IqTotals, now_ms: u64) -> Self {
        Self {
            rx_chainmask: report.rx_chainmask,
            tx_chainmask: report.tx_chainmask,
            limits: limits(report.five_ghz),
            hist: core::array::from_fn(|c| [report.default_nf[c]; HIST]),
            index: [0; 3],
            priv_nf: report.default_nf,
            invalid: [FILTER_WINDOW; 3],
            nfcal_pending: false,
            iq: CalState::Running,
            iq_valid: false,
            samples: 0,
            totals,
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
    pub(in crate::ath9k) fn private_nf(&self) -> [i16; 3] {
        self.priv_nf
    }
    pub(in crate::ath9k) fn nfcal_pending(&self) -> bool {
        self.nfcal_pending
    }
    pub(in crate::ath9k) fn totals(&self) -> IqTotals {
        self.totals
    }

    /// The `ath9k_hw_reset` tail for `AR_SREV_9300_20_OR_LATER`:
    /// `ath9k_hw_loadnf` (its result is ignored there) then
    /// `ath9k_hw_start_nfcal(ah, true)`.
    pub(in crate::ath9k) fn start(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        match self.loadnf(io) {
            Ok(()) | Err(BringUpError::Timeout) => {}
            Err(error) => return Err(error),
        }
        self.start_nfcal(io, true)
    }

    /// `link.c::ath_ani_calibrate` without ANI: long calibration every
    /// 30 s, short calibrations every second while not `caldone`, and the
    /// 20 min `ath9k_hw_reset_calvalid` restart. An `Err` is Linux's
    /// `ath9k_queue_reset(RESET_TYPE_CALIBRATION)`: the caller must close
    /// this generation.
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
            match self.calibrate(io, tick.longcal, &mut tick) {
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

    /// `ar9003_hw_calibrate`: the per-calibration list (one circular
    /// entry, so a finished calibration's `calNext` is itself, `CAL_DONE`),
    /// then on a long calibration `ath9k_hw_getnf`, `ath9k_hw_loadnf`
    /// (`-ETIMEDOUT` propagates) and `ath9k_hw_start_nfcal(ah, false)`.
    fn calibrate(
        &mut self,
        io: &mut impl RegisterIo,
        longcal: bool,
        tick: &mut Tick,
    ) -> Result<bool, BringUpError> {
        let mut iscaldone = true;
        if matches!(self.iq, CalState::Running | CalState::Waiting) {
            iscaldone = self.per_calibration(io, tick)?;
        }
        if longcal && self.getnf(io, tick)? {
            self.loadnf(io)?;
            self.start_nfcal(io, false)?;
        }
        Ok(iscaldone)
    }

    /// `ar9003_hw_per_calibration` for `iq_cal_single_sample` (no
    /// calibration timeout on AR9003).
    fn per_calibration(
        &mut self,
        io: &mut impl RegisterIo,
        tick: &mut Tick,
    ) -> Result<bool, BringUpError> {
        match self.iq {
            CalState::Running => {
                if read(io, AR_PHY_TIMING4)? & AR_PHY_TIMING4_DO_CAL != 0 {
                    return Ok(false);
                }
                self.collect(io)?;
                self.samples = self.samples.saturating_add(1);
                if self.samples >= MIN_CAL_SAMPLES {
                    let chains = self.rx_chainmask.count_ones() as usize;
                    tick.iq = Some(self.iqcalibrate(io, chains)?);
                    self.iq_valid = true;
                    self.iq = CalState::Done;
                    Ok(true)
                } else {
                    setup_iq(io)?;
                    Ok(false)
                }
            }
            _ if !self.iq_valid => {
                self.reset_calibration(io)?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// `calib.c::ath9k_hw_reset_calibration`.
    fn reset_calibration(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        setup_iq(io)?;
        self.iq = CalState::Running;
        self.samples = 0;
        Ok(())
    }

    /// `ar9003_hw_iqcal_collect`: Linux accumulates the chains of
    /// `ah->txchainmask`.
    fn collect(&mut self, io: &mut impl RegisterIo) -> Result<(), BringUpError> {
        for chain in chains(self.tx_chainmask) {
            let at = CAL_MEAS[chain];
            let i = read(io, at)?;
            let q = read(io, at + 4)?;
            let correlation = read(io, at + 8)?;
            self.totals.power_i[chain] = self.totals.power_i[chain].wrapping_add(i);
            self.totals.power_q[chain] = self.totals.power_q[chain].wrapping_add(q);
            self.totals.correlation[chain] =
                self.totals.correlation[chain].wrapping_add(correlation as i32);
        }
        Ok(())
    }

    /// `ar9003_hw_iqcalibrate` over chains `0..num_chains`, then the
    /// chain-0 `IQCORR_ENABLE`.
    fn iqcalibrate(
        &mut self,
        io: &mut impl RegisterIo,
        num_chains: usize,
    ) -> Result<[Option<(u8, u8)>; 3], BringUpError> {
        let mut out = [None; 3];
        for (chain, slot) in out.iter_mut().enumerate().take(num_chains) {
            *slot = iq_coefficients(
                self.totals.power_i[chain],
                self.totals.power_q[chain],
                self.totals.correlation[chain] as u32,
            );
            if let Some((i, q)) = *slot {
                field(io, RX_IQCAL_CORR[chain], IQCORR_Q_I_COFF, 7, u32::from(i))?;
                field(io, RX_IQCAL_CORR[chain], IQCORR_Q_Q_COFF, 0, u32::from(q))?;
            }
        }
        rmw(io, RX_IQCAL_CORR[0], 0, IQCORR_ENABLE)?;
        Ok(out)
    }

    /// `calib.c::ath9k_hw_getnf`: `ar9003_hw_do_getnf` for the receiving
    /// control chains, `ath9k_hw_nf_sanitize` and
    /// `ath9k_hw_update_nfcal_hist_buffer` (`NFCAL_INTF` is never set: no
    /// stuck-beacon path on a station).
    fn getnf(&mut self, io: &mut impl RegisterIo, tick: &mut Tick) -> Result<bool, BringUpError> {
        if read(io, AR_PHY_AGC_CONTROL)? & AGC_NF != 0 {
            return Ok(false);
        }
        let mut nf = [0i16; 3];
        for chain in chains(self.rx_chainmask) {
            let raw = ((read(io, NF_REGS[chain])? >> 20) & 0x1ff) as i16;
            let raw = (raw << 7) >> 7;
            nf[chain] = if raw == 0 {
                0
            } else {
                self.limits.sanitize(raw)
            };
        }
        self.nfcal_pending = false;
        for chain in chains(self.rx_chainmask) {
            self.hist[chain][self.index[chain]] = nf[chain];
            self.index[chain] = (self.index[chain] + 1) % HIST;
            if self.invalid[chain] > 0 {
                self.invalid[chain] -= 1;
                self.priv_nf[chain] = nf[chain];
            } else {
                // ath9k_hw_get_nf_hist_mid: reverse sort, element 2.
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
        let agc = read(io, AR_PHY_AGC_CONTROL)?;
        for chain in chains(self.rx_chainmask) {
            rmw(io, NF_REGS[chain], 0x1ff, nf_field(self.priv_nf[chain]))?;
        }
        if agc & AGC_NF != 0 {
            rmw(io, AR_PHY_AGC_CONTROL, AGC_NF, 0)?;
        }
        rmw(io, AR_PHY_AGC_CONTROL, AGC_ENABLE_NF, 0)?;
        rmw(io, AR_PHY_AGC_CONTROL, AGC_NO_UPDATE_NF, 0)?;
        rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_NF)?;
        let mut loaded = false;
        for _ in 0..22_200 {
            if read(io, AR_PHY_AGC_CONTROL)? & AGC_NF == 0 {
                loaded = true;
                break;
            }
            io.delay_us(10);
        }
        if agc & AGC_NF != 0 {
            if agc & AGC_ENABLE_NF != 0 {
                rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_ENABLE_NF)?;
            }
            if agc & AGC_NO_UPDATE_NF != 0 {
                rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_NO_UPDATE_NF)?;
            }
            rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_NF)?;
        }
        if !loaded {
            return Err(BringUpError::Timeout);
        }
        for chain in chains(self.rx_chainmask) {
            rmw(io, NF_REGS[chain], 0x1ff, nf_field(-50))?;
        }
        Ok(())
    }

    /// `calib.c::ath9k_hw_start_nfcal`.
    fn start_nfcal(&mut self, io: &mut impl RegisterIo, update: bool) -> Result<(), BringUpError> {
        self.nfcal_pending = true;
        rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_ENABLE_NF)?;
        if update {
            rmw(io, AR_PHY_AGC_CONTROL, AGC_NO_UPDATE_NF, 0)?;
        } else {
            rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_NO_UPDATE_NF)?;
        }
        rmw(io, AR_PHY_AGC_CONTROL, 0, AGC_NF)
    }
}

/// `ar9003_hw_iqcalibrate` arithmetic for one chain, in Linux's u32/int32
/// types: the `> 0x80000000` sign test, both denominators non-zero,
/// `iCoff`/`qCoff` clamped to ±63, `iCoff` negated for a non-negative
/// correlation, and both masked to 7 bits.
pub(in crate::ath9k) fn iq_coefficients(
    power_i: u32,
    power_q: u32,
    correlation: u32,
) -> Option<(u8, u8)> {
    let (correlation, negative) = if correlation > 0x8000_0000 {
        ((0xffff_ffff - correlation) + 1, true)
    } else {
        (correlation, false)
    };
    let i_denominator = (power_i / 2 + power_q / 2) / 256;
    let q_denominator = power_q / 64;
    if i_denominator == 0 || q_denominator == 0 {
        return None;
    }
    let mut i_coff = (correlation / i_denominator) as i32;
    let q_coff = (power_i / q_denominator).wrapping_sub(64) as i32;
    i_coff = i_coff.clamp(-63, 63);
    if !negative {
        i_coff = -i_coff;
    }
    let q_coff = q_coff.clamp(-63, 63);
    Some(((i_coff & 0x7f) as u8, (q_coff & 0x7f) as u8))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
