// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_eeprom.c::ath9k_hw_ar9300_set_txpower` for a 20 MHz AR9300
//! channel in either band, with PAPRD off (Linux default:
//! `ar9003_is_paprd_enabled` needs `config.enable_paprd`) and TPC off
//! (`tpc_enabled` default): `ar9003_hw_get_target_power_eeprom` (CCK on
//! 2 GHz, legacy and HT20 targets; the HT40 slots stay zero as in the
//! `memset` array), `ar9003_hw_set_power_per_rate_table` (the 11B/11G/HT20
//! or 11A/HT20 CTL modes, `ath9k_hw_get_scaled_power`),
//! `ar9003_hw_tx_power_regwrite`, `ar9003_hw_calibration_apply` with
//! `ar9003_hw_power_control_override`, `ar9003_hw_selfgen_tpc_txpower` and
//! `AR_PHY_PWRTX_MAX` 0.
//!
//! The plan is computed before the first write. Policy over Linux (never
//! invent board values): a transmit chain with no calibration pier within
//! 1000 MHz (Linux presumes a zero correction) and a ceiling above
//! `MAX_RATE_POWER` are refused.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    eeprom::{fbin2freq, field, modal, modal_base},
    field as set_field, rmw,
    templates::AR9300_EEPROM_BYTES,
};
use crate::ath9k::identity::{BringUpError, RegisterIo};

pub(in crate::ath9k) type Image = [u8; AR9300_EEPROM_BYTES];

/// `hw.h::MAX_RATE_POWER` (half-dBm).
pub(in crate::ath9k) const MAX_RATE_POWER: u16 = 63;
/// `ar9300RateSize`.
pub(in crate::ath9k) const RATES: usize = 36;
const LEGACY_6_24: usize = 0;
const LEGACY_1L_5L: usize = 4;
const HT20_0_8_16: usize = 8;
const HT40_0_8_16: usize = 22;
const SD_NO_CTL: u16 = 0xe0;
const CTL_MODE_M: u16 = 0xf;
const CTL_11A: u16 = 0;
const CTL_11B: u16 = 1;
const CTL_11G: u16 = 2;
const CTL_2GHT20: u16 = 5;
const CTL_5GHT20: u16 = 6;

/// `ar9003_eeprom.c::interpolate` (rounded toward `yb`).
pub(in crate::ath9k) fn interpolate(x: i32, xa: i32, xb: i32, ya: i32, yb: i32) -> i32 {
    let bf = 2 * (yb - ya) * (x - xa) / (xb - xa);
    ya + bf / 2 + bf % 2
}

/// `ar9003_hw_power_interpolate` over unordered `(px, py)` pairs.
pub(in crate::ath9k) fn power_interpolate(x: i32, px: &[i32], py: &[i32]) -> i32 {
    let mut low: Option<(i32, i32)> = None;
    let mut high: Option<(i32, i32)> = None;
    for (&fx, &fy) in px.iter().zip(py) {
        let dx = x - fx;
        if dx <= 0 && high.is_none_or(|(hx, _)| dx > x - hx) {
            high = Some((fx, fy));
        }
        if dx >= 0 && low.is_none_or(|(lx, _)| dx < x - lx) {
            low = Some((fx, fy));
        }
    }
    match (low, high) {
        (Some((lx, ly)), Some((hx, hy))) if hx != lx => interpolate(x, lx, hx, ly, hy),
        (Some((_, ly)), _) => ly,
        (None, Some((_, hy))) => hy,
        (None, None) => -(1 << 30),
    }
}

/// One `tPow2x` table: `count` frequency bins at `bins`, rows of `width`
/// bytes at `rows`.
#[derive(Clone, Copy)]
struct Rows {
    bins: usize,
    rows: usize,
    count: usize,
    width: usize,
}

fn target(image: &Image, two: bool, table: Rows, rate: usize, frequency: u16) -> u8 {
    let mut px = [0; 8];
    let mut py = [0; 8];
    for (i, (x, y)) in px
        .iter_mut()
        .zip(py.iter_mut())
        .take(table.count)
        .enumerate()
    {
        *x = fbin2freq(image[table.bins + i], two);
        *y = i32::from(image[table.rows + i * table.width + rate]);
    }
    power_interpolate(i32::from(frequency), &px[..table.count], &py[..table.count]) as u8
}

/// `ar9003_hw_get_target_power_eeprom` for an HT20 (or legacy) channel.
pub(in crate::ath9k) fn targets(image: &Image, frequency: u16) -> [u8; RATES] {
    let two = frequency < 4000;
    let mut out = [0u8; RATES];
    if two {
        let cck = Rows {
            bins: field::TARGET_FBIN_CCK,
            rows: field::TARGET_CCK,
            count: 2,
            width: 4,
        };
        for rate in 0..4 {
            out[LEGACY_1L_5L + rate] = target(image, true, cck, rate, frequency);
        }
    }
    let (bins, rows, ht_bins, ht_rows, count) = if two {
        (
            field::TARGET_FBIN_2G,
            field::TARGET_2G,
            field::TARGET_FBIN_2G_HT20,
            field::TARGET_2G_HT20,
            3,
        )
    } else {
        (
            field::TARGET_FBIN_5G,
            field::TARGET_5G,
            field::TARGET_FBIN_5G_HT20,
            field::TARGET_5G_HT20,
            8,
        )
    };
    let legacy = Rows {
        bins,
        rows,
        count,
        width: 4,
    };
    let ht20 = Rows {
        bins: ht_bins,
        rows: ht_rows,
        count,
        width: 14,
    };
    for rate in 0..4 {
        out[LEGACY_6_24 + rate] = target(image, two, legacy, rate, frequency);
    }
    for rate in 0..14 {
        out[HT20_0_8_16 + rate] = target(image, two, ht20, rate, frequency);
    }
    out
}

/// `ar9003_hw_get_max_edge_power` (direct / indirect band edge, 2 GHz zero
/// becomes 60).
fn max_edge_power(image: &Image, frequency: u16, index: usize, two: bool) -> u16 {
    let (bins, powers, edges) = if two {
        (
            field::CTL_FREQBIN_2G + 4 * index,
            field::CTL_POWER_2G + 4 * index,
            4,
        )
    } else {
        (
            field::CTL_FREQBIN_5G + 8 * index,
            field::CTL_POWER_5G + 8 * index,
            8,
        )
    };
    let frequency = i32::from(frequency);
    let mut power = MAX_RATE_POWER;
    for edge in 0..edges {
        let bin = image[bins + edge];
        if bin == 0xff {
            break;
        }
        if frequency == fbin2freq(bin, two) {
            power = u16::from(image[powers + edge] & 0x3f);
            break;
        }
        if edge > 0 && frequency < fbin2freq(bin, two) {
            let previous = image[powers + edge - 1];
            power =
                if fbin2freq(image[bins + edge - 1], two) < frequency && (previous >> 6) & 3 != 0 {
                    u16::from(previous & 0x3f)
                } else {
                    MAX_RATE_POWER
                };
            break;
        }
    }
    if two && power == 0 {
        60
    } else {
        power
    }
}

/// `ath9k_hw_get_scaled_power` for `tx_chainmask`.
pub(in crate::ath9k) fn scaled_power(limit: u16, antenna_reduction: u8, tx_chainmask: u8) -> u16 {
    let reduction = u16::from(antenna_reduction)
        + match tx_chainmask.count_ones() {
            2 => 6,
            3 => 10,
            _ => 0,
        };
    limit.saturating_sub(reduction).min(MAX_RATE_POWER)
}

/// `ar9003_hw_set_power_per_rate_table` for a 20 MHz channel.
fn limit(
    image: &Image,
    targets: &mut [u8; RATES],
    frequency: u16,
    ctl: u16,
    antenna_reduction: u8,
    power_limit: u16,
    tx_chainmask: u8,
) {
    let two = frequency < 4000;
    let scaled = scaled_power(power_limit, antenna_reduction, tx_chainmask);
    let modes: &[u16] = if two {
        &[CTL_11B, CTL_11G, CTL_2GHT20]
    } else {
        &[CTL_11A, CTL_5GHT20]
    };
    let (index, count) = if two {
        (field::CTL_INDEX_2G, 12)
    } else {
        (field::CTL_INDEX_5G, 9)
    };
    for &mode in modes {
        let mut max_edge = MAX_RATE_POWER;
        let wanted = (ctl & !CTL_MODE_M) | (mode & CTL_MODE_M);
        for i in 0..count {
            let entry = u16::from(image[index + i]);
            if entry == 0 {
                break;
            }
            if wanted == entry || wanted == (entry & CTL_MODE_M) | SD_NO_CTL {
                let edge = max_edge_power(image, frequency, i, two);
                if ctl & !CTL_MODE_M == SD_NO_CTL {
                    max_edge = max_edge.min(edge);
                } else {
                    max_edge = edge;
                    break;
                }
            }
        }
        let min_ctl = max_edge.min(scaled) as u8;
        let range = match mode {
            CTL_11B => LEGACY_1L_5L..LEGACY_1L_5L + 4,
            CTL_11A | CTL_11G => LEGACY_6_24..LEGACY_6_24 + 4,
            _ => HT20_0_8_16..HT40_0_8_16,
        };
        for value in &mut targets[range] {
            *value = (*value).min(min_ctl);
        }
    }
}

/// `ar9003_hw_tx_power_regwrite`'s twelve `AR_PHY_POWER_TX_RATE` words in
/// write order (rates 0, 1, 2, 3, 8, 4, 5, 9, 10, 6, 7, 11).
pub(in crate::ath9k) fn rate_words(p: &[u8; RATES]) -> [(u64, u32); 12] {
    let pow = |values: [usize; 4]| -> u32 {
        values
            .iter()
            .enumerate()
            .map(|(i, &at)| {
                if at == usize::MAX {
                    0
                } else {
                    (u32::from(p[at]) & 0x3f) << (8 * i)
                }
            })
            .fold(0, |a, b| a | b)
    };
    const N: usize = usize::MAX;
    // Index constants: legacy 0..8, HT20 8..22, HT40 22..36.
    let ht20 = |i: usize| HT20_0_8_16 + i;
    let ht40 = |i: usize| HT40_0_8_16 + i;
    [
        (0xa3c0, pow([0, 0, 0, 0])),
        (0xa3c4, pow([0, 1, 2, 3])),
        (0xa3c8, pow([4, N, 4, 4])),
        (0xa3cc, pow([4, 5, 6, 7])),
        (0xa3e0, pow([4, 0, 4, 0])),
        (0xa3d0, pow([ht20(0), ht20(1), ht20(2), ht20(3)])),
        (0xa3d4, pow([ht20(4), ht20(5), ht20(6), ht20(7)])),
        (0xa3e4, pow([ht20(8), ht20(9), ht20(10), ht20(11)])),
        (0xa3e8, pow([ht20(12), ht20(13), ht40(12), ht40(13)])),
        (0xa3d8, pow([ht40(0), ht40(1), ht40(2), ht40(3)])),
        (0xa3dc, pow([ht40(4), ht40(5), ht40(6), ht40(7)])),
        (0xa3ec, pow([ht40(8), ht40(9), ht40(10), ht40(11)])),
    ]
}

/// `ar9003_hw_cal_pier_get` + `ar9003_hw_calibration_apply` selection for
/// one chain: `(correction, temperature, voltage, nf_cal, nf_pwr)` or
/// `None` when no pier is within 1000 MHz.
fn chain_calibration(image: &Image, frequency: i32, chain: usize) -> Option<[i32; 5]> {
    let two = frequency < 4000;
    let (piers, data, count) = if two {
        (field::PIERS_2G, field::CAL_2G, 3)
    } else {
        (field::PIERS_5G, field::CAL_5G, 8)
    };
    let pier = |i: usize| -> (i32, [i32; 5]) {
        let at = data + (chain * count + i) * 6;
        let n2dbm = |p: u8| ((i32::from(p as i8) + 3) >> 2) - 90;
        let nf = image[at + 5] != 0;
        (
            fbin2freq(image[piers + i], two),
            [
                i32::from(image[at] as i8),
                i32::from(image[at + 2]),
                i32::from(image[at + 1]),
                if nf { n2dbm(image[at + 3]) } else { 0 },
                if nf { n2dbm(image[at + 4]) } else { 0 },
            ],
        )
    };
    let (mut lf, mut hf) = (0i32, 100_000i32);
    let (mut lv, mut hv) = ([0i32; 5], [0i32; 5]);
    for i in 0..count {
        let (pf, values) = pier(i);
        let fdiff = frequency - pf;
        if fdiff <= 0 && (hf <= 0 || hf >= 100_000 || fdiff > frequency - hf) {
            hf = pf;
            hv = values;
        }
        if fdiff >= 0 && (lf <= 0 || fdiff < frequency - lf) {
            lf = pf;
            lv = values;
        }
    }
    if hf == lf {
        Some(lv)
    } else if frequency - lf < 1000 {
        if hf - frequency < 1000 {
            Some(core::array::from_fn(|k| {
                interpolate(frequency, lf, hf, lv[k], hv[k])
            }))
        } else {
            Some(lv)
        }
    } else if hf - frequency < 1000 {
        Some(hv)
    } else {
        None
    }
}

/// `ar9003_hw_power_control_override`'s temperature slope (AR9300 paths).
fn temp_slope(image: &Image, frequency: i32) -> i32 {
    let signed = |at: usize| i32::from(image[at] as i8);
    if frequency < 4000 {
        return signed(field::MODAL_2G + modal::TEMP_SLOPE);
    }
    if image[field::MISC_CONFIGURATION] & 0x20 != 0 {
        // FBIN2FREQ (no unused-bin check).
        let f: [i32; 8] =
            core::array::from_fn(|i| 4800 + 5 * i32::from(image[field::PIERS_5G + i]));
        let t: [i32; 8] =
            core::array::from_fn(|i| signed(field::EXT1 + field::EXT1_TEMPSLOPE_EXTENSION + i));
        power_interpolate(frequency, &f, &t)
    } else if image[field::EXT2 + field::EXT2_TEMP_SLOPE_LOW] != 0 {
        power_interpolate(
            frequency,
            &[5180, 5500, 5785],
            &[
                signed(field::EXT2 + field::EXT2_TEMP_SLOPE_LOW),
                signed(field::MODAL_5G + modal::TEMP_SLOPE),
                signed(field::EXT2 + field::EXT2_TEMP_SLOPE_HIGH),
            ],
        )
    } else {
        signed(field::MODAL_5G + modal::TEMP_SLOPE)
    }
}

/// The complete AR9300 transmit-power plan for one 20 MHz channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Plan {
    pub frequency: u16,
    /// `targetPowerValT2` after CTL limiting (half-dBm).
    pub targets: [u8; RATES],
    /// `regulatory->max_power_level` before
    /// `ath9k_hw_update_regulatory_maxpower`.
    pub max_power_level: u8,
    pub correction: [i32; 3],
    pub temperature: [i32; 3],
    pub voltage: [i32; 3],
    /// `ah->nf_2g`/`nf_5g` `.cal` and `.pwr` (`ath9k_hw_loadnf` inputs).
    pub nf_cal: [i32; 3],
    pub nf_power: [i32; 3],
    pub temp_slope: i32,
    pub tx_chainmask: u8,
}

/// `ath9k_hw_apply_txpower` → `ath9k_hw_ar9300_set_txpower` planning:
/// `ctl` is `ath9k_regd_get_ctl`, `power_limit` the half-dBm
/// `min(chan max_power * 2, reg->power_limit)`; the antenna reduction is
/// the band's `antennaGain` (`get_antenna_gain`).
pub(in crate::ath9k) fn plan(
    image: &Image,
    frequency: u16,
    ctl: u16,
    power_limit: u8,
    tx_chainmask: u8,
) -> Result<Plan, BringUpError> {
    if u16::from(power_limit) > MAX_RATE_POWER || tx_chainmask == 0 || tx_chainmask & !7 != 0 {
        return Err(BringUpError::BadCalibration);
    }
    let two = frequency < 4000;
    let mut targets = targets(image, frequency);
    let gain = image[modal_base(!two) + modal::ANTENNA_GAIN];
    limit(
        image,
        &mut targets,
        frequency,
        ctl,
        gain,
        u16::from(power_limit),
        tx_chainmask,
    );
    let max_power_level = targets.iter().copied().max().unwrap_or(0);
    let f = i32::from(frequency);
    let mut values = [[0i32; 5]; 3];
    for (chain, slot) in values.iter_mut().enumerate() {
        match chain_calibration(image, f, chain) {
            Some(v) => *slot = v,
            None if tx_chainmask & (1 << chain) != 0 => return Err(BringUpError::BadCalibration),
            None => {}
        }
    }
    Ok(Plan {
        frequency,
        targets,
        max_power_level,
        correction: core::array::from_fn(|c| values[c][0]),
        temperature: core::array::from_fn(|c| values[c][1]),
        voltage: core::array::from_fn(|c| values[c][2]),
        nf_cal: core::array::from_fn(|c| values[c][3]),
        nf_power: core::array::from_fn(|c| values[c][4]),
        temp_slope: temp_slope(image, f),
        tx_chainmask,
    })
}

/// Program a [`Plan`]: `AR_PHY_TX_FORCED_GAIN` 0, the rate words, the
/// open-loop gain delta / error-estimate / temperature slope overrides,
/// `AR_TPC` and `AR_PHY_PWRTX_MAX` 0 (TPC disabled).
pub(in crate::ath9k) fn program(io: &mut impl RegisterIo, plan: &Plan) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(0xa458, 0);
    for (register, value) in rate_words(&plan.targets) {
        io.write32(register, value);
    }
    // ar9003_hw_power_control_override: `REG_RMW(.., correction << 16,
    // AR_PHY_TPC_OLPC_GAIN_DELTA)` ORs the unmasked (sign-extended) shift.
    for (chain, register) in [0xa420u64, 0xb420, 0xc420].into_iter().enumerate() {
        if chain == 0 || plan.tx_chainmask & (1 << chain) != 0 {
            rmw(
                io,
                register,
                0x00ff_0000,
                (plan.correction[chain] << 16) as u32,
            )?;
        }
    }
    for (chain, register) in [0xa40cu64, 0xb40c, 0xc40c].into_iter().enumerate() {
        if chain == 0 || plan.tx_chainmask & (1 << chain) != 0 {
            rmw(io, register, 0x0300_0000, 3 << 24)?;
        }
    }
    set_field(io, 0xa440, 0xff, 0, plan.temp_slope as u32)?;
    set_field(io, 0xa43c, 0xff, 0, plan.temperature[0] as u32)?;
    // ar9003_hw_selfgen_tpc_txpower: ACK/CTS at the lowest rate's power.
    let ack = u32::from(if plan.frequency < 4000 {
        plan.targets[LEGACY_1L_5L]
    } else {
        plan.targets[LEGACY_6_24]
    }) & 0x3f;
    io.write32(0x80e8, ack | (ack << 8) | (0x3f << 16) | (0x3f << 24));
    io.write32(0xa3f0, 0);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
