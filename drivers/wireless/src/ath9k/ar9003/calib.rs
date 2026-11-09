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
//! `ATH9K_HW_CAP_RTT` nor MCI), the `ath9k_hw_reset` tail's
//! `ath9k_hw_loadnf` + `ath9k_hw_start_nfcal(ah, true)`, and the periodic
//! `ar9003_hw_calibrate` driven by `link.c::ath_ani_calibrate` (ANI is not
//! part of this owner), with the AR9300 `ar9003_hw_set_nf_limits` limits
//! and the `ar9300_cca_regs` control-chain NF registers. On MCI parts
//! the MCI calibration handshake (`mci::init_cal_req` / `init_cal_done`,
//! `mci::start_reset` / `end_reset`) wraps this calibration when the
//! link is enabled; the handshake lives in `mci`, not here.
//!
//! The per-chip branches of `ar9003_hw_init_cal_settings`:
//! `TX_IQ_CAL` is `AR_SREV_9300_20_OR_LATER` (every modeled chip) and
//! `TX_IQ_ON_AGC_CAL` is `AR_SREV_9485_OR_LATER` non-9340 (AR9485,
//! AR9462, AR9565). On `TX_IQ_ON_AGC_CAL` chips `run` sets
//! `AR_PHY_TX_IQCAL_CONTROL_0` `ENABLE_TXIQ_CAL` and, after the AGC
//! calibration, runs `ar9003_hw_tx_iq_cal_post_proc` (chan-info reads,
//! `ar9003_hw_calc_iq_corr`, `ar9003_hw_tx_iq_cal_outlier_detection`
//! with its not-9485 `CORR_COEFF_B1/B2` table); the saved coefficients
//! are the `TXIQCAL_DONE` state a fast channel change would
//! `ar9003_hw_tx_iq_cal_reload` (not-9485 table likewise). On AR9300
//! neither runs, exactly as before. The periodic RX IQ calibration
//! aborts on a saturated (±63) coefficient on AR9565
//! (`ar9003_calib.c:273`); the calibration is still marked done, only
//! the writes and the `IQCORR_ENABLE` are skipped.
//!
//! TX IQ calibration as Linux runs it on AR9300: `ar9003_hw_init_cal_settings`
//! enables `TX_IQ_CAL`, so `init_cal_pcoem` programs the
//! `AR_PHY_TX_IQCAL_CONTROL_1` `DELPT` field; without `TX_IQ_ON_AGC_CAL`
//! `txiqcal_done` stays false, `ath9k_hw_reset` cleared `TXIQCAL_DONE`, and
//! neither `ar9003_hw_tx_iq_cal_post_proc` nor `_reload` runs. The
//! carrier-leak table copy into `caldata->tx_clcal` is not kept:
//! `ath9k_hw_reset` clears `TXCLCAL_DONE` before every full-reset
//! `init_cal`, so only the (unported) fast channel change would reload it.
//!
//! Not ported: the AR9550 three-pass `ar955x_tx_iq_cal_median` (no
//! AR9550 is modeled) and `ar9003_hw_dynamic_osdac_selection` with its
//! `ar9003_hw_tx_iq_cal` caller; both are follow-ups, not silent gaps.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{eeprom::Identity, field, phy::Prepared, rmw, Revision};
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
/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CONTROL_1(ah)` on AR9485
/// (`AR_SM_BASE + 0x3c8`).
const AR_PHY_TX_IQCAL_CONTROL_1_9485: u64 = 0xa5c8;
const DELPT_MASK: u32 = 0x01fc_0000;
const DELPT_SHIFT: u32 = 18;
/// `ar9003_calib.c` `DELPT`.
const DELPT: u32 = 32;
/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CONTROL_0(ah)` (`AR_SM_BASE + 0x444`,
/// `0x3c4` on AR9485) and its `ENABLE_TXIQ_CAL` bit.
const AR_PHY_TX_IQCAL_CONTROL_0: u64 = 0xa644;
const AR_PHY_TX_IQCAL_CONTROL_0_9485: u64 = 0xa5c4;
const TXIQCAL_CONTROL_0_ENABLE_TXIQ_CAL: u32 = 0x8000_0000;
/// `ar9003_phy.h::AR_PHY_TX_IQCAL_STATUS_B{0,1,2}(ah)` (`AR_SM_BASE` +
/// `0x48c`, `0x3f0` on AR9485; `AR_SM1_BASE`/`AR_SM2_BASE` + `0x48c`),
/// its `FAILED` bit and the `CALIBRATED_GAINS_0` field.
const AR_PHY_TX_IQCAL_STATUS_B0: u64 = 0xa68c;
const AR_PHY_TX_IQCAL_STATUS_B0_9485: u64 = 0xa5f0;
const AR_PHY_TX_IQCAL_STATUS_B1: u64 = 0xb68c;
const AR_PHY_TX_IQCAL_STATUS_B2: u64 = 0xc68c;
const TX_IQCAL_STATUS_FAILED: u32 = 0x1;
const CALIBRATED_GAINS_0_MASK: u32 = 0x3e;
const CALIBRATED_GAINS_0_SHIFT: u32 = 1;
/// `ar9003_phy.h::AR_PHY_CHAN_INFO_MEMORY(ah)` (`AR_SM_BASE + 0x170`,
/// non-AR9561), its `TAB_S2_READ` field and the per-chain
/// `AR_PHY_CHAN_INFO_TAB_{0,1,2}` bases.
const AR_PHY_CHAN_INFO_MEMORY: u64 = 0xa370;
const CHAN_INFO_TAB_S2_READ_MASK: u32 = 0x8;
const CHAN_INFO_TAB_S2_READ_SHIFT: u32 = 3;
const CHAN_INFO_TAB: [u64; 3] = [0x9b00, 0xab00, 0xbb00];
/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CORR_COEFF_B{0,1,2}(ah, i)`
/// (`AR_SM_BASE` + `0x450` + 4i, `0x3d0` + 4i on AR9485 for B0;
/// `AR_SM1_BASE`/`AR_SM2_BASE` + `0x450` + 4i) and the `00`/`01`
/// `COEFF_TABLE` fields.
const AR_PHY_TX_IQCAL_CORR_COEFF_B0: u64 = 0xa650;
const AR_PHY_TX_IQCAL_CORR_COEFF_B0_9485: u64 = 0xa5d0;
const AR_PHY_TX_IQCAL_CORR_COEFF_B1: u64 = 0xb650;
const AR_PHY_TX_IQCAL_CORR_COEFF_B2: u64 = 0xc650;
const COEFF_00_TABLE_MASK: u32 = 0x0000_3fff;
const COEFF_00_TABLE_SHIFT: u32 = 0;
const COEFF_01_TABLE_MASK: u32 = 0x0fff_c000;
const COEFF_01_TABLE_SHIFT: u32 = 14;
/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CONTROL_3` (`AR_CHAN_BASE + 0xb0`)
/// and its `IQCORR_EN` bit; `AR_PHY_RX_IQCAL_CORR_B0`'s
/// `LOOPBACK_IQCORR_EN` bit.
const AR_PHY_TX_IQCAL_CONTROL_3: u64 = 0x98b0;
const TX_IQCAL_CONTROL_3_IQCORR_EN: u32 = 0x8000_0000;
const RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN: u32 = 0x2000_0000;
/// `hw.h::MAX_IQCAL_MEASUREMENT` and `ar9003_calib.c::MAXIQCAL`.
const MAX_MEASUREMENT: usize = 8;
/// `ar9003_calib.c::MAX_MAG_DELTA` / `MAX_PHS_DELTA`.
const MAX_MAG_DELTA: i32 = 11;
const MAX_PHS_DELTA: i32 = 10;
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
    /// `ar9003_hw_tx_iq_cal_post_proc`'s saved coefficients
    /// (`TXIQCAL_DONE`): `Some` only on `TX_IQ_ON_AGC_CAL` chips when the
    /// post-processing succeeded; `None` on AR9300/AR9580 and when the TX
    /// IQ calibration failed.
    pub tx_iq_cal: Option<TxIqCal>,
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
    /// `Periodic::start` performs the reset tail's NF load. `revision`
    /// gates the per-chip branches: `TX_IQ_ON_AGC_CAL` (AR9485, AR9462,
    /// AR9565) runs the TX IQ post-processing after the AGC calibration.
    ///
    /// # Safety
    /// Exclusive identified AR9003 part directly after `phy::prepare` for
    /// `prepared`. PCI BME off, no published packet DMA, MAC/TX/IRQ parked.
    /// A new attempt requires an independently proved complete reset.
    pub(in crate::ath9k) async unsafe fn run(
        &mut self,
        io: &mut impl Io,
        identity: &Identity,
        revision: &Revision,
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
        // `ar9003_hw_init_cal_settings` (`:321-323`) + `init_cal_pcoem`:
        // `TX_IQ_CAL` programs `DELPT`; on `TX_IQ_ON_AGC_CAL` chips the
        // AGC calibration also runs the TX IQ calibration.
        let cals = enabled_cals(revision);
        if cals.tx_iq_cal {
            field(
                io,
                tx_iqcal_control_1(revision.ar9485()),
                DELPT_MASK,
                DELPT_SHIFT,
                DELPT,
            )?;
        }
        let txiqcal_done = if cals.tx_iq_on_agc_cal {
            // Fresh channel calibration data: `TXIQCAL_DONE` is clear, as
            // `ath9k_hw_reset` leaves it.
            rmw(
                io,
                tx_iqcal_control_0(revision.ar9485()),
                0,
                TXIQCAL_CONTROL_0_ENABLE_TXIQ_CAL,
            )?;
            true
        } else {
            false
        };
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
        // `init_cal_pcoem`: the TX IQ post-processing runs before
        // `ar9003_hw_cl_cal_post_proc`; a failed TX IQ calibration leaves
        // no coefficients and the reset continues.
        let tx_iq_cal = if txiqcal_done {
            tx_iq_cal_post_proc(io, revision, tx)?
        } else {
            None
        };
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
            tx_iq_cal,
        };
        self.report = Some(report);
        *attempt.state = State::Ready;
        Ok(report)
    }
}

/// `ar9003_hw_init_cal_settings`' `enabled_cals` for this chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct EnabledCals {
    pub tx_iq_cal: bool,
    pub tx_iq_on_agc_cal: bool,
}

/// `ar9003_hw_init_cal_settings` (`ar9003_calib.c:321-323`): `TX_IQ_CAL`
/// for `AR_SREV_9300_20_OR_LATER`, and `TX_IQ_ON_AGC_CAL` for
/// `AR_SREV_9485_OR_LATER` non-9340. Every modeled chip has `TX_IQ_CAL`;
/// AR9485, AR9462 and AR9565 additionally have `TX_IQ_ON_AGC_CAL`.
pub(in crate::ath9k) fn enabled_cals(revision: &Revision) -> EnabledCals {
    let tx_iq_cal = revision.ar9300_20_or_later();
    EnabledCals {
        tx_iq_cal,
        tx_iq_on_agc_cal: tx_iq_cal && revision.ar9485_or_later() && !revision.ar9340(),
    }
}

/// `struct ath9k_hw_cal_data`'s TX IQ calibration result
/// (`hw.h::MAX_IQCAL_MEASUREMENT` x `AR9300_MAX_CHAINS`): the per-chain
/// measurement counts and correction coefficients
/// `ar9003_hw_tx_iq_cal_outlier_detection` writes, and
/// `ar9003_hw_tx_iq_cal_reload` re-applies. `Some` in a `Report` is the
/// `TXIQCAL_DONE` state `ar9003_hw_tx_iq_cal_outlier_detection` sets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct TxIqCal {
    pub num_measures: [usize; 3],
    pub tx_corr_coeff: [[i32; 3]; MAX_MEASUREMENT],
}

/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CONTROL_1(ah)`.
fn tx_iqcal_control_1(ar9485: bool) -> u64 {
    if ar9485 {
        AR_PHY_TX_IQCAL_CONTROL_1_9485
    } else {
        AR_PHY_TX_IQCAL_CONTROL_1
    }
}

/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CONTROL_0(ah)`.
fn tx_iqcal_control_0(ar9485: bool) -> u64 {
    if ar9485 {
        AR_PHY_TX_IQCAL_CONTROL_0_9485
    } else {
        AR_PHY_TX_IQCAL_CONTROL_0
    }
}

/// `ar9003_phy.h::AR_PHY_TX_IQCAL_STATUS_B{0,1,2}(ah)` for `chain`.
fn tx_iqcal_status(chain: usize, ar9485: bool) -> u64 {
    match chain {
        0 => {
            if ar9485 {
                AR_PHY_TX_IQCAL_STATUS_B0_9485
            } else {
                AR_PHY_TX_IQCAL_STATUS_B0
            }
        }
        1 => AR_PHY_TX_IQCAL_STATUS_B1,
        _ => AR_PHY_TX_IQCAL_STATUS_B2,
    }
}

/// `ar9003_phy.h::AR_PHY_TX_IQCAL_CORR_COEFF_B{0,1,2}(ah, i)` for `chain`
/// and measurement pair `i`.
fn tx_iqcal_corr_coeff(chain: usize, ar9485: bool, i: usize) -> u64 {
    let base = match chain {
        0 => {
            if ar9485 {
                AR_PHY_TX_IQCAL_CORR_COEFF_B0_9485
            } else {
                AR_PHY_TX_IQCAL_CORR_COEFF_B0
            }
        }
        1 => AR_PHY_TX_IQCAL_CORR_COEFF_B1,
        _ => AR_PHY_TX_IQCAL_CORR_COEFF_B2,
    };
    base + (i as u64) * 4
}

/// `ar9003_hw_find_mag_approx`: `max - max/32 + min/8 + min/4`.
fn find_mag_approx(in_re: i64, in_im: i64) -> i64 {
    let (max_abs, min_abs) = if in_re.abs() > in_im.abs() {
        (in_re.abs(), in_im.abs())
    } else {
        (in_im.abs(), in_re.abs())
    };
    max_abs - max_abs / 32 + min_abs / 8 + min_abs / 4
}

/// The eight inputs to the 4x4 loopback IQ calibration solve, bundled so
/// `solve_iq_cal` stays under clippy's argument limit.
struct IqCalSolveParams {
    sin_2phi_1: i64,
    cos_2phi_1: i64,
    sin_2phi_2: i64,
    cos_2phi_2: i64,
    mag_a0_d0: i64,
    phs_a0_d0: i64,
    mag_a1_d0: i64,
    phs_a1_d0: i64,
}

/// `ar9003_hw_solve_iq_cal`: the 4x4 loopback IQ calibration solve.
/// Linux computes in `s32`; the products can exceed `s32` for
/// out-of-range inputs, so the port widens the intermediates to `i64` —
/// identical results for every in-range input, no wrap on any other.
fn solve_iq_cal(params: IqCalSolveParams) -> Option<[i64; 4]> {
    let IqCalSolveParams {
        sin_2phi_1,
        cos_2phi_1,
        sin_2phi_2,
        cos_2phi_2,
        mag_a0_d0,
        phs_a0_d0,
        mag_a1_d0,
        phs_a1_d0,
    } = params;
    const RESULT_SHIFT: i64 = 1 << 15;
    let f1 = cos_2phi_1 - cos_2phi_2;
    let f3 = sin_2phi_1 - sin_2phi_2;
    let f2 = ((f1 >> 3) * (f1 >> 3) + (f3 >> 3) * (f3 >> 3)) >> 9;
    if f2 == 0 {
        return None;
    }
    let mag_tx = (f1 * (mag_a0_d0 - mag_a1_d0) + f3 * (phs_a0_d0 - phs_a1_d0)) / f2;
    let phs_tx = (f3 * (-mag_a0_d0 + mag_a1_d0) + f1 * (phs_a0_d0 - phs_a1_d0)) / f2;
    let mag_rx = mag_a0_d0 - (cos_2phi_1 * mag_tx + sin_2phi_1 * phs_tx) / RESULT_SHIFT;
    let phs_rx = phs_a0_d0 + (sin_2phi_1 * mag_tx - cos_2phi_1 * phs_tx) / RESULT_SHIFT;
    Some([mag_tx, phs_tx, mag_rx, phs_rx])
}

/// Clamp a TX IQ correction factor to ±63 (`ar9003_hw_calc_iq_corr`).
fn clamp63(value: i64) -> i32 {
    value.clamp(-63, 63) as i32
}

/// `ar9003_hw_calc_iq_corr`: the TX/RX IQ correction factors for one
/// chain from six chan-info words. Returns `[tx, rx]`, or `None` on a
/// failed calculation. The unpacking is Linux's, including the
/// asymmetric detail that `i2_p_q2_a0_d1` is not sign-extended.
fn calc_iq_corr(iq_res: &[i32; 6]) -> Option<[i32; 2]> {
    const RES_SCALE: i64 = 1 << 15;
    const DELPT_SHIFT: i64 = 1 << 8;
    /// `calc_iq_corr`'s 12-bit sign extension (`> 0x800` wraps negative).
    fn extend(value: i64) -> i64 {
        if value > 0x800 {
            -((0xfff - value) + 1)
        } else {
            value
        }
    }
    let i2_m_q2_a0_d0 = extend(i64::from(iq_res[0] & 0xfff));
    let i2_p_q2_a0_d0 = extend(i64::from((iq_res[0] >> 12) & 0xfff));
    let iq_corr_a0_d0 = extend(i64::from(
        ((iq_res[0] >> 24) & 0xff) + ((iq_res[1] & 0xf) << 8),
    ));
    let i2_m_q2_a0_d1 = extend(i64::from((iq_res[1] >> 4) & 0xfff));
    let i2_p_q2_a0_d1 = i64::from(iq_res[2] & 0xfff);
    let iq_corr_a0_d1 = extend(i64::from((iq_res[2] >> 12) & 0xfff));
    let i2_m_q2_a1_d0 = extend(i64::from(
        ((iq_res[2] >> 24) & 0xff) + ((iq_res[3] & 0xf) << 8),
    ));
    let i2_p_q2_a1_d0 = extend(i64::from((iq_res[3] >> 4) & 0xfff));
    let iq_corr_a1_d0 = extend(i64::from(iq_res[4] & 0xfff));
    let i2_m_q2_a1_d1 = extend(i64::from((iq_res[4] >> 12) & 0xfff));
    let i2_p_q2_a1_d1 = extend(i64::from(
        ((iq_res[4] >> 24) & 0xff) + ((iq_res[5] & 0xf) << 8),
    ));
    let iq_corr_a1_d1 = extend(i64::from((iq_res[5] >> 4) & 0xfff));
    if i2_p_q2_a0_d0 == 0 || i2_p_q2_a0_d1 == 0 || i2_p_q2_a1_d0 == 0 || i2_p_q2_a1_d1 == 0 {
        return None;
    }
    if !(1024..=2047).contains(&i2_p_q2_a0_d0)
        || i2_p_q2_a1_d0 < 0
        || i2_p_q2_a1_d1 < 0
        || i2_p_q2_a0_d0 <= i2_m_q2_a0_d0
        || i2_p_q2_a0_d0 <= iq_corr_a0_d0
        || i2_p_q2_a0_d1 <= i2_m_q2_a0_d1
        || i2_p_q2_a0_d1 <= iq_corr_a0_d1
        || i2_p_q2_a1_d0 <= i2_m_q2_a1_d0
        || i2_p_q2_a1_d0 <= iq_corr_a1_d0
        || i2_p_q2_a1_d1 <= i2_m_q2_a1_d1
        || i2_p_q2_a1_d1 <= iq_corr_a1_d1
    {
        return None;
    }
    let mag_a0_d0 = i2_m_q2_a0_d0 * RES_SCALE / i2_p_q2_a0_d0;
    let phs_a0_d0 = iq_corr_a0_d0 * RES_SCALE / i2_p_q2_a0_d0;
    let mag_a0_d1 = i2_m_q2_a0_d1 * RES_SCALE / i2_p_q2_a0_d1;
    let phs_a0_d1 = iq_corr_a0_d1 * RES_SCALE / i2_p_q2_a0_d1;
    let mag_a1_d0 = i2_m_q2_a1_d0 * RES_SCALE / i2_p_q2_a1_d0;
    let phs_a1_d0 = iq_corr_a1_d0 * RES_SCALE / i2_p_q2_a1_d0;
    let mag_a1_d1 = i2_m_q2_a1_d1 * RES_SCALE / i2_p_q2_a1_d1;
    let phs_a1_d1 = iq_corr_a1_d1 * RES_SCALE / i2_p_q2_a1_d1;
    let mut sin_2phi_1 = (mag_a0_d0 - mag_a0_d1) * DELPT_SHIFT / i64::from(DELPT);
    let mut cos_2phi_1 = (phs_a0_d1 - phs_a0_d0) * DELPT_SHIFT / i64::from(DELPT);
    let mut sin_2phi_2 = (mag_a1_d0 - mag_a1_d1) * DELPT_SHIFT / i64::from(DELPT);
    let mut cos_2phi_2 = (phs_a1_d1 - phs_a1_d0) * DELPT_SHIFT / i64::from(DELPT);
    let mag1 = find_mag_approx(cos_2phi_1, sin_2phi_1);
    let mag2 = find_mag_approx(cos_2phi_2, sin_2phi_2);
    if mag1 == 0 || mag2 == 0 {
        return None;
    }
    sin_2phi_1 = sin_2phi_1 * RES_SCALE / mag1;
    cos_2phi_1 = cos_2phi_1 * RES_SCALE / mag1;
    sin_2phi_2 = sin_2phi_2 * RES_SCALE / mag2;
    cos_2phi_2 = cos_2phi_2 * RES_SCALE / mag2;
    let [mag_tx, phs_tx, mag_rx, phs_rx] = solve_iq_cal(IqCalSolveParams {
        sin_2phi_1,
        cos_2phi_1,
        sin_2phi_2,
        cos_2phi_2,
        mag_a0_d0,
        phs_a0_d0,
        mag_a1_d0,
        phs_a1_d0,
    })?;
    if RES_SCALE == mag_tx {
        return None;
    }
    let mag_corr_tx = mag_tx * RES_SCALE / (RES_SCALE - mag_tx);
    let phs_corr_tx = -phs_tx;
    let q_q_coff = clamp63(mag_corr_tx * 128 / RES_SCALE);
    let q_i_coff = clamp63(phs_corr_tx * 256 / RES_SCALE);
    let tx = q_q_coff * 128 + (0x7f & q_i_coff);
    if -mag_rx == RES_SCALE {
        return None;
    }
    let mag_corr_rx = -mag_rx * RES_SCALE / (RES_SCALE + mag_rx);
    let phs_corr_rx = -phs_rx;
    let q_q_coff = clamp63(mag_corr_rx * 128 / RES_SCALE);
    let q_i_coff = clamp63(phs_corr_rx * 256 / RES_SCALE);
    let rx = q_q_coff * 128 + (0x7f & q_i_coff);
    Some([tx, rx])
}

/// `ar9003_hw_detect_outlier` for one chain's single-pass (`[0]`)
/// column: the min/max mismatch, the mean excluding the largest absolute
/// value, and the outlier replaced by the mean when the spread exceeds
/// `max_delta`.
fn detect_outlier(coeff: &mut [i32; MAX_MEASUREMENT], nmeasurement: usize, max_delta: i32) {
    if nmeasurement == 0 {
        // Linux reads `mp_coeff[nmeasurement - 1]` here; with no
        // measurement there is nothing to detect.
        return;
    }
    let mut mp_max = -64;
    let mut max_idx = 0;
    let mut mp_min = 63;
    let mut min_idx = 0;
    for (i, &value) in coeff.iter().enumerate().take(nmeasurement) {
        if value > mp_max {
            mp_max = value;
            max_idx = i;
        } else if value < mp_min {
            mp_min = value;
            min_idx = i;
        }
    }
    let mut mp_avg = 0;
    let mut mp_count = 0;
    for &value in coeff.iter().take(nmeasurement) {
        if value.abs() < mp_max.abs() || value.abs() < mp_min.abs() {
            mp_avg += value;
            mp_count += 1;
        }
    }
    if mp_count != 0 {
        mp_avg /= mp_count;
    } else {
        mp_avg = coeff[nmeasurement - 1];
    }
    if (mp_max - mp_min).abs() > max_delta {
        let outlier_idx = if (mp_max - mp_avg).abs() > (mp_min - mp_avg).abs() {
            max_idx
        } else {
            min_idx
        };
        coeff[outlier_idx] = mp_avg;
    }
}

/// `ar9003_hw_tx_iq_cal_outlier_detection`'s and
/// `ar9003_hw_tx_iq_cal_reload`'s `tx_corr_coeff` table:
/// `CORR_COEFF_B0(ah, i)` for measurement pairs, plus `B1`/`B2` only
/// when not AR9485 (`ar9003_calib.c:901`, `:1162`). Unpopulated entries
/// are 0, as Linux's `memset` leaves them.
fn corr_coeff_table(ar9485: bool) -> [[u64; 3]; MAX_MEASUREMENT] {
    let mut table = [[0u64; 3]; MAX_MEASUREMENT];
    for i in 0..MAX_MEASUREMENT / 2 {
        table[i * 2][0] = tx_iqcal_corr_coeff(0, ar9485, i);
        table[i * 2 + 1][0] = tx_iqcal_corr_coeff(0, ar9485, i);
        if !ar9485 {
            table[i * 2][1] = tx_iqcal_corr_coeff(1, ar9485, i);
            table[i * 2 + 1][1] = tx_iqcal_corr_coeff(1, ar9485, i);
            table[i * 2][2] = tx_iqcal_corr_coeff(2, ar9485, i);
            table[i * 2 + 1][2] = tx_iqcal_corr_coeff(2, ar9485, i);
        }
    }
    table
}

/// `ar9003_hw_tx_iq_cal_outlier_detection` for the single `iqcal_idx == 0`
/// pass: per-chain outlier detection (skipped on AR9550, which is not
/// modeled), the `iqc_coeff` table writes and the `TXIQCAL_DONE` state
/// (`is_reusable` is always true here: no MCI). Also sets
/// `AR_PHY_TX_IQCAL_CONTROL_3` `IQCORR_EN` and
/// `AR_PHY_RX_IQCAL_CORR_B0` `LOOPBACK_IQCORR_EN`.
fn tx_iq_cal_outlier_detection(
    io: &mut impl RegisterIo,
    revision: &Revision,
    tx_chainmask: u8,
    mag: &mut [[i32; MAX_MEASUREMENT]; 3],
    phs: &mut [[i32; MAX_MEASUREMENT]; 3],
) -> Result<TxIqCal, BringUpError> {
    let table = corr_coeff_table(revision.ar9485());
    let mut data = TxIqCal::default();
    for chain in chains(tx_chainmask) {
        let mut nmeasurement = ((read(io, tx_iqcal_status(0, revision.ar9485()))?
            & CALIBRATED_GAINS_0_MASK)
            >> CALIBRATED_GAINS_0_SHIFT) as usize;
        if nmeasurement > MAX_MEASUREMENT {
            nmeasurement = MAX_MEASUREMENT;
        }
        if nmeasurement > 1 {
            detect_outlier(&mut mag[chain], nmeasurement, MAX_MAG_DELTA);
            detect_outlier(&mut phs[chain], nmeasurement, MAX_PHS_DELTA);
        }
        for im in 0..nmeasurement {
            let magnitude = mag[chain][im];
            let phase = phs[chain][im];
            let coeff = (phase & 0x7f) | ((magnitude & 0x7f) << 7);
            let register = table[im][chain];
            if im % 2 == 0 {
                field(
                    io,
                    register,
                    COEFF_00_TABLE_MASK,
                    COEFF_00_TABLE_SHIFT,
                    coeff as u32,
                )?;
            } else {
                field(
                    io,
                    register,
                    COEFF_01_TABLE_MASK,
                    COEFF_01_TABLE_SHIFT,
                    coeff as u32,
                )?;
            }
            data.tx_corr_coeff[im][chain] = coeff;
        }
        data.num_measures[chain] = nmeasurement;
    }
    rmw(
        io,
        AR_PHY_TX_IQCAL_CONTROL_3,
        0,
        TX_IQCAL_CONTROL_3_IQCORR_EN,
    )?;
    rmw(io, RX_IQCAL_CORR[0], 0, RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN)?;
    Ok(data)
}

/// `ar9003_hw_tx_iq_cal_post_proc(ah, 0, true)`: the single-pass TX IQ
/// calibration `ar9003_hw_init_cal_pcoem` runs on a `TX_IQ_ON_AGC_CAL`
/// chip after the AGC calibration. Returns the saved coefficients
/// (`TXIQCAL_DONE`), or `None` when the calibration failed — Linux logs
/// and continues the reset without coefficients. The AR9550 three-pass
/// median is not implemented (no AR9550 is modeled): `outlier_detect`
/// stays true, so outlier detection always runs.
fn tx_iq_cal_post_proc(
    io: &mut impl RegisterIo,
    revision: &Revision,
    tx_chainmask: u8,
) -> Result<Option<TxIqCal>, BringUpError> {
    let ar9485 = revision.ar9485();
    let mut mag = [[0i32; MAX_MEASUREMENT]; 3];
    let mut phs = [[0i32; MAX_MEASUREMENT]; 3];
    for chain in chains(tx_chainmask) {
        let mut nmeasurement = ((read(io, tx_iqcal_status(0, ar9485))? & CALIBRATED_GAINS_0_MASK)
            >> CALIBRATED_GAINS_0_SHIFT) as usize;
        if nmeasurement > MAX_MEASUREMENT {
            nmeasurement = MAX_MEASUREMENT;
        }
        for im in 0..nmeasurement {
            if read(io, tx_iqcal_status(chain, ar9485))? & TX_IQCAL_STATUS_FAILED != 0 {
                return Ok(None);
            }
            let mut iq_res = [0i32; 6];
            for j in 0..3 {
                let idx = 2 * j;
                let offset = (4 * (3 * im + j)) as u64;
                field(
                    io,
                    AR_PHY_CHAN_INFO_MEMORY,
                    CHAN_INFO_TAB_S2_READ_MASK,
                    CHAN_INFO_TAB_S2_READ_SHIFT,
                    0,
                )?;
                iq_res[idx] = read(io, CHAN_INFO_TAB[chain] + offset)? as i32;
                field(
                    io,
                    AR_PHY_CHAN_INFO_MEMORY,
                    CHAN_INFO_TAB_S2_READ_MASK,
                    CHAN_INFO_TAB_S2_READ_SHIFT,
                    1,
                )?;
                iq_res[idx + 1] = (read(io, CHAN_INFO_TAB[chain] + offset)? & 0xffff) as i32;
            }
            let Some(iqc) = calc_iq_corr(&iq_res) else {
                return Ok(None);
            };
            phs[chain][im] = iqc[0] & 0x7f;
            mag[chain][im] = (iqc[0] >> 7) & 0x7f;
            if mag[chain][im] > 63 {
                mag[chain][im] -= 128;
            }
            if phs[chain][im] > 63 {
                phs[chain][im] -= 128;
            }
        }
    }
    Ok(Some(tx_iq_cal_outlier_detection(
        io,
        revision,
        tx_chainmask,
        &mut mag,
        &mut phs,
    )?))
}

/// `ar9003_hw_tx_iq_cal_reload`: re-apply saved TX IQ coefficients on a
/// fast channel change (`TXIQCAL_DONE` set). Only the (unported) fast
/// channel change calls it; `run` never does. The not-9485 `B1`/`B2`
/// table is `ar9003_calib.c:1162`.
pub(in crate::ath9k) fn tx_iq_cal_reload(
    io: &mut impl RegisterIo,
    revision: &Revision,
    tx_chainmask: u8,
    data: &TxIqCal,
) -> Result<(), BringUpError> {
    let table = corr_coeff_table(revision.ar9485());
    for chain in chains(tx_chainmask) {
        for (im, row) in table
            .iter()
            .enumerate()
            .take(data.num_measures[chain].min(MAX_MEASUREMENT))
        {
            let register = row[chain];
            let coeff = data.tx_corr_coeff[im][chain];
            if im % 2 == 0 {
                field(
                    io,
                    register,
                    COEFF_00_TABLE_MASK,
                    COEFF_00_TABLE_SHIFT,
                    coeff as u32,
                )?;
            } else {
                field(
                    io,
                    register,
                    COEFF_01_TABLE_MASK,
                    COEFF_01_TABLE_SHIFT,
                    coeff as u32,
                )?;
            }
        }
    }
    rmw(
        io,
        AR_PHY_TX_IQCAL_CONTROL_3,
        0,
        TX_IQCAL_CONTROL_3_IQCORR_EN,
    )?;
    rmw(io, RX_IQCAL_CORR[0], 0, RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN)?;
    Ok(())
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
    revision: Revision,
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
    pub(in crate::ath9k) fn new(
        revision: &Revision,
        report: &Report,
        totals: IqTotals,
        now_ms: u64,
    ) -> Self {
        Self {
            revision: *revision,
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
    /// chain-0 `IQCORR_ENABLE`. On AR9565 a saturated (±63) coefficient
    /// aborts the whole calibration (`ar9003_calib.c:273`): that chain
    /// and later chains are not written and the enable is skipped — the
    /// caller still marks the calibration done, as Linux does.
    fn iqcalibrate(
        &mut self,
        io: &mut impl RegisterIo,
        num_chains: usize,
    ) -> Result<[Option<(u8, u8)>; 3], BringUpError> {
        let mut out = [None; 3];
        for (chain, slot) in out.iter_mut().enumerate().take(num_chains) {
            let Some(coeff) = iq_coefficients(
                self.totals.power_i[chain],
                self.totals.power_q[chain],
                self.totals.correlation[chain] as u32,
            ) else {
                continue;
            };
            if self.revision.ar9565() && coeff.saturated {
                return Ok(out);
            }
            field(
                io,
                RX_IQCAL_CORR[chain],
                IQCORR_Q_I_COFF,
                7,
                u32::from(coeff.i),
            )?;
            field(
                io,
                RX_IQCAL_CORR[chain],
                IQCORR_Q_Q_COFF,
                0,
                u32::from(coeff.q),
            )?;
            *slot = Some((coeff.i, coeff.q));
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

/// One chain's `ar9003_hw_iqcalibrate` coefficients: the 7-bit fields
/// and whether either hit the ±63 clamp (on AR9565 a saturated
/// coefficient aborts the whole calibration, `ar9003_calib.c:273`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct IqCoefficients {
    pub i: u8,
    pub q: u8,
    pub saturated: bool,
}

/// `ar9003_hw_iqcalibrate` arithmetic for one chain, in Linux's u32/int32
/// types: the `> 0x80000000` sign test, both denominators non-zero,
/// `iCoff`/`qCoff` clamped to ±63, `iCoff` negated for a non-negative
/// correlation, and both masked to 7 bits.
pub(in crate::ath9k) fn iq_coefficients(
    power_i: u32,
    power_q: u32,
    correlation: u32,
) -> Option<IqCoefficients> {
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
    let saturated = i_coff == 63 || i_coff == -63 || q_coff == 63 || q_coff == -63;
    Some(IqCoefficients {
        i: (i_coff & 0x7f) as u8,
        q: (q_coff & 0x7f) as u8,
        saturated,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
