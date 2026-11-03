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
//! `eeprom_def.c::ath9k_hw_def_set_txpower` for an AR9280 20 MHz channel in
//! either band, closed-loop only: `ath9k_hw_set_def_power_per_rate_table`
//! (per-band legacy/HT20 targets, CTL per band on
//! `ctlEdges[ntxchains - 1]`), `ath9k_hw_set_def_power_cal_table` with
//! `eeprom.c::ath9k_hw_get_gain_boundaries_pdadcs`,
//! `ath9k_change_gain_boundary_setting` and `ath9k_adjust_pdadc_values`,
//! then the rate registers with `pwr_table_offset * 2` removed and TPC off.
//!
//! The whole plan is validated before the first write. Inputs on which
//! Linux would index out of bounds (`pwr_table_offset` below
//! `AR5416_PWR_TABLE_OFFSET_DB` or a shift of 128+ PDADC entries) or whose
//! six-bit `ATH9K_POW_SM` fields would wrap are refused instead.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{minor, open_loop, MODAL_2G, MODAL_5G};
use crate::{
    ath9k::{
        chips::MAP_DEF,
        identity::{eeprom_word, BringUpError, Identity, RegisterIo},
        phy::{
            channel::Tune,
            power::{indices, interpolate, vpd},
            rates::{initial_ctl, initial_ctl_5ghz, limit_with},
            rmw,
        },
    },
    qualcomm_regulatory::Factory,
};

const TX_MASK: usize = 19;
const PWR_TABLE_OFFSET: usize = 41;
/// `modal_eep_header` offsets.
const ANTENNA_GAIN: usize = 16;
const XPD_GAIN: usize = 38;
const PD_GAIN_OVERLAP: usize = 46;
const DECREASE_2_CHAIN: usize = 50;
const DECREASE_3_CHAIN: usize = 51;
/// `ar5416_eeprom_def` offsets.
const PIERS_5G: usize = 336;
const PIERS_2G: usize = 344;
const CAL_5G: usize = 348;
const CAL_2G: usize = 1308;
const CAL_STRIDE: usize = 40;
const TARGET_5G: usize = 1788;
const TARGET_5G_HT20: usize = 1828;
const TARGET_CCK: usize = 1972;
const TARGET_2G: usize = 1987;
const TARGET_2G_HT20: usize = 2007;
const CTL_INDEX: usize = 2079;
const CTL_DATA: usize = 2103;
const CTL_STRIDE: usize = 48;
/// `AR5416_PWR_TABLE_OFFSET_DB`, `MAX_RATE_POWER`.
const DEFAULT_TABLE_OFFSET: i16 = -5;
const MAX_RATE_POWER: u16 = 63;

/// `ath9k_hw_fbin2freq`.
fn fbin2freq(bin: u8, two: bool) -> u16 {
    if two {
        2300 + u16::from(bin)
    } else {
        4800 + 5 * u16::from(bin)
    }
}

/// `eeprom.c::ath9k_hw_get_legacy_target_powers` / `_get_target_powers`
/// over `count` `{bChannel, tPow2x[N]}` rows. An empty list (on which Linux
/// indexes `powInfo[-1]`), unordered channels or a power above 63 are
/// refused.
fn target<const N: usize>(
    image: &[u8],
    at: usize,
    count: usize,
    frequency: u16,
    two: bool,
) -> Result<[u8; N], BringUpError> {
    let row = |i: usize| &image[at + i * (N + 1)..at + (i + 1) * (N + 1)];
    let used = (0..count).position(|i| row(i)[0] == 255).unwrap_or(count);
    if used == 0 {
        return Err(BringUpError::BadCalibration);
    }
    for i in 0..used {
        if row(i)[1..].iter().any(|p| *p > 63) || (i > 0 && row(i - 1)[0] >= row(i)[0]) {
            return Err(BringUpError::BadCalibration);
        }
    }
    let freq = |i: usize| fbin2freq(row(i)[0], two);
    let (mut matched, mut low) = (None, None);
    if frequency <= freq(0) {
        matched = Some(0);
    } else {
        for i in 0..used {
            if frequency == freq(i) {
                matched = Some(i);
                break;
            }
            if i > 0 && frequency < freq(i) && frequency > freq(i - 1) {
                low = Some(i - 1);
                break;
            }
        }
        if matched.is_none() && low.is_none() {
            matched = Some(used - 1);
        }
    }
    if let Some(i) = matched {
        return Ok(core::array::from_fn(|r| row(i)[r + 1]));
    }
    let low = low.unwrap_or(0);
    let (a, b) = (row(low), row(low + 1));
    Ok(core::array::from_fn(|r| {
        interpolate(frequency, freq(low), freq(low + 1), a[r + 1], b[r + 1])
    }))
}

/// `eeprom.c::ath9k_hw_get_max_edge_power` over `AR5416_NUM_BAND_EDGES`
/// `{bChannel, ctl}` edges.
fn edge_power(edges: &[u8], frequency: u16, two: bool) -> Result<u8, BringUpError> {
    let used = edges.chunks_exact(2).position(|e| e[0] == 255).unwrap_or(8);
    for i in 1..used {
        if edges[(i - 1) * 2] >= edges[i * 2] {
            return Err(BringUpError::BadCalibration);
        }
    }
    for i in 0..used {
        let f = fbin2freq(edges[i * 2], two);
        if frequency == f {
            return Ok(edges[i * 2 + 1] & 63);
        }
        if i > 0 && frequency < f {
            let previous = edges[(i - 1) * 2 + 1];
            if fbin2freq(edges[(i - 1) * 2], two) < frequency && previous >> 6 != 0 {
                return Ok(previous & 63);
            }
            break;
        }
    }
    Ok(63)
}

/// One TX chain's detector table (`AR_PHY_TPCRG5` + 32 PDADC words).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Chain {
    pub tpcrg5: u32,
    pub pdadc: [u32; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Plan {
    /// `xpdGainValues[0..3]` and `numXpdGain`.
    pub gains: [u16; 3],
    pub count: usize,
    pub chains: [Option<Chain>; 2],
    /// `regulatory->max_power_level` after the chain correction.
    pub max_power: u8,
    /// RATE1, RATE2, [RATE3, RATE4 on 2 GHz], RATE5, RATE6, TX_SUB,
    /// RATE_MAX (TPC off).
    pub registers: [(u64, u32); 8],
    pub register_count: usize,
}

/// `ath9k_hw_get_gain_boundaries_pdadcs` for one chain's
/// `cal_data_per_freq` rows, then `ath9k_change_gain_boundary_setting` and
/// `ath9k_adjust_pdadc_values` (AR9280_20_OR_LATER).
fn detector(
    image: &[u8],
    data: usize,
    piers: &[u8],
    bin: u8,
    count: usize,
    overlap: u8,
    diff: i16,
) -> Result<Chain, BringUpError> {
    let (left, right) = indices(bin, piers);
    let mut minimum = [0u8; 4];
    let mut maximum = [0u8; 4];
    let mut tables = [[0u8; 64]; 4];
    for gain in 0..count {
        let mut parts = [([0u8; 5], [0u8; 5]); 2];
        for (slot, pier) in [left, right].into_iter().enumerate() {
            let at = data + pier * CAL_STRIDE + gain * 5;
            parts[slot].0.copy_from_slice(&image[at..at + 5]);
            parts[slot].1.copy_from_slice(&image[at + 20..at + 25]);
            if parts[slot].0.windows(2).any(|w| w[0] > w[1])
                || parts[slot].1.windows(2).any(|w| w[0] > w[1])
            {
                return Err(BringUpError::BadCalibration);
            }
        }
        minimum[gain] = parts[0].0[0].max(parts[1].0[0]);
        maximum[gain] = parts[0].0[4].min(parts[1].0[4]);
        let range = maximum[gain]
            .checked_sub(minimum[gain])
            .filter(|r| (2..=126).contains(r))
            .ok_or(BringUpError::BadCalibration)?;
        let a = vpd(minimum[gain], maximum[gain], &parts[0].0, &parts[0].1);
        let b = vpd(minimum[gain], maximum[gain], &parts[1].0, &parts[1].1);
        for i in 0..=usize::from(range / 2) {
            tables[gain][i] = interpolate(
                u16::from(bin),
                u16::from(piers[left]),
                u16::from(piers[right]),
                a[i],
                b[i],
            );
        }
    }
    let mut bounds = [0u16; 4];
    let mut values = [0u8; 128];
    let mut k = 0;
    for gain in 0..count {
        bounds[gain] = (if gain == count - 1 {
            u16::from(maximum[gain]) / 2
        } else {
            (u16::from(maximum[gain]) + u16::from(minimum[gain + 1])) / 4
        })
        .min(MAX_RATE_POWER);
        // AR9280_20_OR_LATER starts the first gain at -minPwrT4 / 2.
        let mut offset = if gain == 0 {
            -(i16::from(minimum[gain]) / 2)
        } else {
            bounds[gain - 1] as i16 - i16::from(minimum[gain]) / 2 - i16::from(overlap) + 1
        };
        let first = tables[gain][0];
        let step = (i16::from(tables[gain][1]) - i16::from(first)).max(1);
        while offset < 0 && k < 127 {
            values[k] = (i16::from(first) + offset * step).max(0) as u8;
            k += 1;
            offset += 1;
        }
        let size = usize::from((maximum[gain] - minimum[gain]) / 2) + 1;
        // Linux narrows tgtIndex to u8 before selecting its cap.
        let target =
            (bounds[gain] as i16 + i16::from(overlap) - i16::from(minimum[gain]) / 2) as u8;
        let limit = usize::from(target).min(size) as i16;
        while offset < limit && k < 127 {
            values[k] = tables[gain][offset as usize];
            k += 1;
            offset += 1;
        }
        let last = tables[gain][size - 1];
        let step = (i16::from(last) - i16::from(tables[gain][size - 2])).max(1);
        if i16::from(target) >= limit {
            while offset <= i16::from(target) && k < 127 {
                values[k] = (i16::from(last) + (offset - limit + 1) * step).min(255) as u8;
                k += 1;
                offset += 1;
            }
        }
    }
    if k == 0 {
        return Err(BringUpError::BadCalibration);
    }
    // Non-4k maps fill the unused boundaries with the last computed one.
    for gain in count..4 {
        bounds[gain] = bounds[count - 1];
    }
    while k < 128 {
        values[k] = values[k - 1];
        k += 1;
    }
    // ath9k_change_gain_boundary_setting: only the computed boundaries move
    // by `diff` half-dB steps (u16 arithmetic), then cap at 63 - overlap.
    let limit = MAX_RATE_POWER - u16::from(overlap);
    for bound in bounds.iter_mut().take(count) {
        *bound = bound.wrapping_sub(diff as u16).min(limit);
    }
    // ath9k_adjust_pdadc_values: shift the table to start at the offset.
    if diff != 0 {
        let keep = 128 - diff as usize;
        for k in 0..keep {
            values[k] = values[k + diff as usize];
        }
        let fill = values[keep];
        for value in values.iter_mut().skip(keep) {
            *value = fill;
        }
    }
    let mut tpcrg5 = u32::from(overlap) & 0xf;
    for (i, bound) in bounds.iter().enumerate() {
        tpcrg5 |= (u32::from(*bound) & 0x3f) << (4 + 6 * i);
    }
    Ok(Chain {
        tpcrg5,
        pdadc: core::array::from_fn(|j| {
            u32::from_le_bytes(values[4 * j..4 * j + 4].try_into().unwrap())
        }),
    })
}

/// The complete transmit-power plan at `ceiling` half-dBm
/// (`reg->power_limit`); `overlap_register` is the live `AR_PHY_TPCRG5`
/// overlap used below minor 2.
pub(in crate::ath9k) fn plan(
    identity: &Identity,
    image: &[u8],
    tune: Tune,
    ceiling: u8,
    overlap_register: u8,
) -> Result<Plan, BringUpError> {
    if image.len() != MAP_DEF.bytes() {
        return Err(BringUpError::BadLength);
    }
    if tune.is_wide() || u16::from(ceiling) > MAX_RATE_POWER || open_loop(identity, image) {
        return Err(BringUpError::BadCalibration);
    }
    let tx_mask = image[TX_MASK];
    if tx_mask == 0 || tx_mask > 3 {
        return Err(BringUpError::BadIdentity);
    }
    let two = !tune.is_5ghz();
    let frequency = tune.center();
    let modal = if two { MODAL_2G } else { MODAL_5G };
    let chains = tx_mask.count_ones() as usize;
    let minor = minor(identity);

    // ath9k_hw_set_def_power_per_rate_table. EEP_ANTENNA_GAIN_2G/5G is the
    // max over all three map entries (`get_antenna_gain`).
    let gain = image[modal + ANTENNA_GAIN]
        .max(image[modal + ANTENNA_GAIN + 1])
        .max(image[modal + ANTENNA_GAIN + 2]);
    let correction = if chains == 2 { 6 } else { 0 };
    let scaled = u16::from(ceiling)
        .saturating_sub(u16::from(gain) + correction)
        .min(MAX_RATE_POWER) as u8;
    let factory = Factory::from_eeprom(u32::from(eeprom_word(image, 8)))
        .map_err(|_| BringUpError::BadCalibration)?;
    let ctl = |cfg_ctl: u16, mode: u16| {
        limit_with(
            &image[CTL_INDEX..CTL_INDEX + 24],
            |i| {
                let at = CTL_DATA + i * CTL_STRIDE + (chains - 1) * 16;
                edge_power(&image[at..at + 16], frequency, two)
            },
            cfg_ctl,
            mode,
            scaled,
        )
    };
    let mut cck = [0u8; 4];
    let (mut ofdm, mut ht20);
    if two {
        let cfg = initial_ctl(factory);
        cck = target::<4>(image, TARGET_CCK, 3, frequency, true)?;
        ofdm = target::<4>(image, TARGET_2G, 4, frequency, true)?;
        ht20 = target::<8>(image, TARGET_2G_HT20, 4, frequency, true)?;
        // CTL_11B, CTL_11G, CTL_2GHT20.
        for (mode, powers) in [(1, &mut cck[..]), (2, &mut ofdm[..]), (5, &mut ht20[..])] {
            let allowed = ctl(cfg, mode)?;
            powers.iter_mut().for_each(|p| *p = (*p).min(allowed));
        }
    } else {
        let cfg = initial_ctl_5ghz(factory);
        ofdm = target::<4>(image, TARGET_5G, 8, frequency, false)?;
        ht20 = target::<8>(image, TARGET_5G_HT20, 8, frequency, false)?;
        // CTL_11A, CTL_5GHT20.
        for (mode, powers) in [(0, &mut ofdm[..]), (6, &mut ht20[..])] {
            let allowed = ctl(cfg, mode)?;
            powers.iter_mut().for_each(|p| *p = (*p).min(allowed));
        }
    }
    let max_power = cck
        .iter()
        .chain(&ofdm)
        .chain(&ht20)
        .copied()
        .max()
        .unwrap_or(0)
        + correction as u8;

    // ath9k_hw_set_def_power_cal_table.
    let mask = image[modal + XPD_GAIN];
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
    let overlap = if minor >= 2 {
        image[modal + PD_GAIN_OVERLAP]
    } else {
        overlap_register
    };
    if overlap > 15 {
        return Err(BringUpError::BadCalibration);
    }
    let table_offset = if minor >= 0x15 {
        i16::from(image[PWR_TABLE_OFFSET] as i8)
    } else {
        DEFAULT_TABLE_OFFSET
    };
    let diff = (table_offset - DEFAULT_TABLE_OFFSET) * 2;
    if !(0..128).contains(&diff) {
        return Err(BringUpError::BadCalibration);
    }
    let (pier_list, pier_count, cal, stride) = if two {
        (PIERS_2G, 4, CAL_2G, 4)
    } else {
        (PIERS_5G, 8, CAL_5G, 8)
    };
    let piers = &image[pier_list..pier_list + pier_count];
    let piers = &piers[..piers.iter().position(|b| *b == 255).unwrap_or(pier_count)];
    if piers.is_empty() || piers.windows(2).any(|w| w[0] >= w[1]) {
        return Err(BringUpError::BadCalibration);
    }
    // FREQ2FBIN(synth_center, IS_CHAN_2GHZ).
    let bin = if two {
        (frequency - 2300) as u8
    } else {
        ((frequency - 4800) / 5) as u8
    };
    let mut table = [None; 2];
    for (chain, slot) in table.iter_mut().enumerate() {
        if tx_mask & (1 << chain) != 0 {
            let data = cal + chain * stride * CAL_STRIDE;
            *slot = Some(detector(image, data, piers, bin, count, overlap, diff)?);
        }
    }

    // Rates: `ratesArray[i] -= pwr_table_offset * 2`, ATH9K_POW_SM six bits.
    let mut bad = false;
    let mut pack = |powers: [u8; 4]| -> u32 {
        powers.into_iter().enumerate().fold(0, |v, (i, p)| {
            let value = i16::from(p) - table_offset * 2;
            bad |= !(0..=63).contains(&value);
            v | ((value as u32 & 0x3f) << (8 * i))
        })
    };
    let mut registers = [(0u64, 0u32); 8];
    let mut n = 0;
    let mut push = |register: u64, value: u32| {
        registers[n] = (register, value);
        n += 1;
    };
    push(0x9934, pack([ofdm[0]; 4]));
    push(0x9938, pack([ofdm[0], ofdm[1], ofdm[2], ofdm[3]]));
    if two {
        // rate1l, rateXr (= OFDM 6M), rate2l, rate2s.
        push(0xa234, pack([cck[0], ofdm[0], cck[1], cck[1]]));
        push(0xa238, pack([cck[2], cck[2], cck[3], cck[3]]));
    }
    push(0xa38c, pack(ht20[..4].try_into().unwrap()));
    push(0xa390, pack(ht20[4..].try_into().unwrap()));
    // AR_PHY_POWER_TX_SUB: pwrDecreaseFor3Chain << 6 | pwrDecreaseFor2Chain.
    push(
        0xa3c8,
        ((u32::from(image[modal + DECREASE_3_CHAIN]) & 0x3f) << 6)
            | (u32::from(image[modal + DECREASE_2_CHAIN]) & 0x3f),
    );
    push(0x993c, 63); // ah->tpc_enabled is false: MAX_RATE_POWER, TPC off.
    if bad {
        return Err(BringUpError::BadCalibration);
    }
    Ok(Plan {
        gains,
        count,
        chains: table,
        max_power,
        registers,
        register_count: n,
    })
}

/// Validate the plan, then write `AR_PHY_TPCRG1`, each TX chain's
/// `AR_PHY_TPCRG5` and PDADC table, and the rate registers in Linux order.
pub(in crate::ath9k) fn program(
    io: &mut impl RegisterIo,
    identity: &Identity,
    image: &[u8],
    tune: Tune,
    ceiling: u8,
) -> Result<Plan, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    // Below minor 2 Linux reads the overlap from the live AR_PHY_TPCRG5.
    let live = if minor(identity) >= 2 {
        0
    } else {
        io.read32(0xa26c)
    };
    if live == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    let p = plan(identity, image, tune, ceiling, (live & 0xf) as u8)?;
    for (mask, shift, value) in [
        (0xc000, 14, (p.count - 1) as u16 & 3),
        (0x30000, 16, p.gains[0]),
        (0xc0000, 18, p.gains[1]),
        (0x300000, 20, p.gains[2]),
    ] {
        rmw(io, 0xa258, mask, (u32::from(value) << shift) & mask)?;
    }
    for (chain, table) in p.chains.iter().enumerate() {
        let Some(table) = table else { continue };
        let offset = chain as u64 * 0x1000;
        io.write32(0xa26c + offset, table.tpcrg5);
        for (j, word) in table.pdadc.iter().enumerate() {
            io.write32(0xa280 + offset + j as u64 * 4, *word);
        }
        if !io.authorized() {
            return Err(BringUpError::DeviceGone);
        }
    }
    for &(register, value) in &p.registers[..p.register_count] {
        io.write32(register, value);
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(p)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
