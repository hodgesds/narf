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
//! AR9287 20 MHz transmit power: `eeprom_9287.c::ath9k_hw_ar9287_set_txpower`
//! with `ath9k_hw_set_ar9287_power_per_rate_table` (per-rate targets, CTL
//! limits on the active-chain edge set, two-chain scaled power) and
//! `ath9k_hw_set_ar9287_power_cal_table` (PD gains plus the open-loop
//! reference power per chain, `ar9287_eeprom_olpc_set_pdadcs`).
//!
//! Closed-loop maps (`openLoopPwrCntl == 0`) are refused: with
//! `AR9287_PD_GAIN_ICEPTS == 1`, Linux's `ath9k_hw_fill_vpd_table` sets
//! `idxL = numIntercepts - 2` (u16 65535) and indexes `pPwrList[idxL]`, and
//! `ath9k_hw_get_gain_boundaries_pdadcs` reads `vpdTableI[i][1]` /
//! `[sizeCurrVpdTable - 2]` of a one-entry table, so there is no defined
//! detector table to mirror.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::MODAL;
use crate::{
    ath9k::{
        chips::MAP_9287,
        identity::{eeprom_word, BringUpError, RegisterIo},
        phy::{
            rates::{edge_power, initial_ctl, limit_with, target},
            rmw,
        },
    },
    qualcomm_regulatory::Factory,
};

/// `baseEepHeader.txMask`.
const TX_MASK: usize = 19;
/// `baseEepHeader.openLoopPwrCntl`.
const OPEN_LOOP: usize = 31;
/// `modalHeader.antennaGainCh[2]`.
const ANTENNA_GAIN: usize = MODAL + 12;
/// `modalHeader.xpdGain`.
const XPD_GAIN: usize = MODAL + 26;
/// `calFreqPier2G[3]`.
const PIERS: usize = 195;
/// `calPierData2G[2][3]`: unions of `struct cal_data_op_loop_ar9287`.
const CAL: usize = 198;
const CAL_STRIDE: usize = 40;
/// `cal_data_op_loop_ar9287.vpdPdg` within one pier.
const OPEN_VPD: usize = 10;
const TARGET_CCK: usize = 438;
const TARGET_OFDM: usize = 453;
const TARGET_HT20: usize = 468;
const CTL_INDEX: usize = 522;
const CTL_DATA: usize = 534;
/// `struct cal_ctl_data_ar9287`: two chain sets of four edges.
const CTL_STRIDE: usize = 16;
/// `POWER_CORRECTION_FOR_TWO_CHAIN` (10*log10(2)*2).
const TWO_CHAIN: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Plan {
    /// `xpdGainValues[0..3]` and `numXpdGain`.
    pub gains: [u16; 3],
    pub count: usize,
    /// Open-loop reference power (`txPower & 0xff`) per enabled chain.
    pub olpc: [Option<u8>; 2],
    /// `ah->initPDADC`: chain 0, pier 0 `vpdPdg[0][0]`.
    pub init_pdadc: u8,
    /// `regulatory->max_power_level` after the chain correction.
    pub max_power: u8,
    /// AR_PHY_POWER_TX_RATE1..6 then AR_PHY_POWER_TX_RATE_MAX (TPC off).
    pub registers: [(u64, u32); 7],
}

/// `ar9287_eeprom_get_tx_gain_index`: `pwrPdg[0][0]` of the matching pier,
/// or the C-truncated mean of the two bracketing piers.
fn olpc_power(image: &[u8], chain: usize, piers: &[u8], bin: u8) -> u8 {
    let (left, right) = crate::ath9k::phy::power::indices(bin, piers);
    let power = |pier: usize| image[CAL + (chain * 3 + pier) * CAL_STRIDE] as i8;
    let value = if left == right {
        power(left)
    } else {
        ((i16::from(power(left)) + i16::from(power(right))) / 2) as i8
    };
    value as u8
}

pub(in crate::ath9k) fn plan(
    image: &[u8],
    frequency: u16,
    ceiling: u8,
) -> Result<Plan, BringUpError> {
    if image.len() != MAP_9287.bytes() {
        return Err(BringUpError::BadLength);
    }
    if !(2412..=2484).contains(&frequency) || ceiling > 40 {
        return Err(BringUpError::BadCalibration);
    }
    if image[OPEN_LOOP] == 0 {
        return Err(BringUpError::BadCalibration);
    }
    let tx_mask = image[TX_MASK];
    if !MAP_9287.chainmask_valid(tx_mask) {
        return Err(BringUpError::BadIdentity);
    }
    let chains = tx_mask.count_ones() as usize;
    let bin = (frequency - 2300) as u8;

    // Per-rate table: `ath9k_hw_get_scaled_power` with the antenna gain
    // (`max_t(u8, antennaGainCh[0], antennaGainCh[1])`) and the two-chain
    // correction, then the 11B/11G/HT20 CTL modes on `ctlEdges[chains - 1]`.
    let gain = image[ANTENNA_GAIN].max(image[ANTENNA_GAIN + 1]);
    let reduction = u16::from(gain) + if chains == 2 { u16::from(TWO_CHAIN) } else { 0 };
    let scaled = u16::from(ceiling).saturating_sub(reduction) as u8;
    let factory = Factory::from_eeprom(u32::from(eeprom_word(image, 8)))
        .map_err(|_| BringUpError::BadCalibration)?;
    let cfg_ctl = initial_ctl(factory);
    let mut cck = target::<4>(image, TARGET_CCK, frequency)?;
    let mut ofdm = target::<4>(image, TARGET_OFDM, frequency)?;
    let mut ht20 = target::<8>(image, TARGET_HT20, frequency)?;
    for (mode, powers) in [(1, &mut cck[..]), (2, &mut ofdm[..]), (5, &mut ht20[..])] {
        let allowed = limit_with(
            &image[CTL_INDEX..CTL_INDEX + 12],
            |i| {
                let at = CTL_DATA + i * CTL_STRIDE + (chains - 1) * 8;
                edge_power(&image[at..at + 8], frequency)
            },
            cfg_ctl,
            mode,
            scaled,
        )?;
        for power in powers {
            *power = (*power).min(allowed);
        }
    }
    let max_power = cck
        .iter()
        .chain(&ofdm)
        .chain(&ht20)
        .copied()
        .max()
        .unwrap_or(0)
        + if chains == 2 { TWO_CHAIN } else { 0 };

    // Power calibration table: xpdGain bits 3..0 give descending PD gains.
    let mask = image[XPD_GAIN];
    if mask == 0 || mask & !15 != 0 {
        return Err(BringUpError::BadCalibration);
    }
    let mut gains = [0u16; 3];
    let mut count = 0;
    for bit in (0..4u16).rev() {
        if mask & (1 << bit) != 0 {
            if count < 3 {
                gains[count] = bit;
            }
            count += 1;
        }
    }
    let piers = &image[PIERS..PIERS + 3];
    let piers = &piers[..piers.iter().position(|b| *b == 255).unwrap_or(3)];
    if piers.is_empty() || piers.windows(2).any(|w| w[0] >= w[1]) {
        return Err(BringUpError::BadCalibration);
    }
    let mut olpc = [None; 2];
    for (chain, slot) in olpc.iter_mut().enumerate() {
        if tx_mask & (1 << chain) != 0 {
            *slot = Some(olpc_power(image, chain, piers, bin));
        }
    }

    // `ratesArray[i] -= AR9287_PWR_TABLE_OFFSET_DB * 2`; every value is at
    // most the 40 half-dB ceiling, so ATH9K_POW_SM's six bits never wrap.
    let pack = |powers: [u8; 4]| -> u32 {
        powers
            .into_iter()
            .enumerate()
            .fold(0, |v, (i, p)| v | (u32::from(p + 10) << (8 * i)))
    };
    Ok(Plan {
        gains,
        count,
        olpc,
        init_pdadc: image[CAL + OPEN_VPD],
        max_power,
        registers: [
            (0x9934, pack([ofdm[0]; 4])),
            (0x9938, pack(ofdm)),
            (0xa234, pack([cck[0], ofdm[0], cck[1], cck[1]])),
            (0xa238, pack([cck[2], cck[2], cck[3], cck[3]])),
            (0xa38c, pack(ht20[..4].try_into().unwrap())),
            (0xa390, pack(ht20[4..].try_into().unwrap())),
            (0x993c, 63), // ah->tpc_enabled is false: MAX_RATE_POWER, TPC off.
        ],
    })
}

/// Validate the whole plan, then write it in Linux order: TPCRG1 PD gains,
/// each enabled chain's OLPC enable and reference power, the six HT20 rate
/// registers and the TPC-disabled maximum.
pub(in crate::ath9k) fn program(
    io: &mut impl RegisterIo,
    image: &[u8],
    frequency: u16,
    ceiling: u8,
) -> Result<Plan, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let p = plan(image, frequency, ceiling)?;
    for (mask, shift, value) in [
        (0xc000, 14, (p.count - 1) as u16 & 3),
        (0x30000, 16, p.gains[0]),
        (0xc0000, 18, p.gains[1]),
        (0x300000, 20, p.gains[2]),
    ] {
        rmw(io, 0xa258, mask, (u32::from(value) << shift) & mask)?;
    }
    for (chain, power) in p.olpc.iter().enumerate() {
        let Some(power) = power else { continue };
        // Both chains' OLPC enables are rewritten on every enabled chain.
        rmw(io, 0xa270, 0x0300_0000, 0x0300_0000)?;
        rmw(io, 0xb270, 0x0300_0000, 0x0300_0000)?;
        rmw(
            io,
            0xa398 + chain as u64 * 0x1000,
            0x00ff_0000,
            u32::from(*power) << 16,
        )?;
    }
    for (register, value) in p.registers {
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
        io.write32(register, value);
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(p)
}

#[cfg(any(test, feature = "kernel-test"))]
pub(in crate::ath9k) mod tests;
