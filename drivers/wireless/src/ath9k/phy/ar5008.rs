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
//! AR5008-PHY (AR5416/AR5418 and AR9160, external AR2133/AR5133 radio)
//! inactive 20 MHz baseband preparation, in `hw.c::ath9k_hw_reset` order:
//! `ath9k_hw_init_pll` (`ar5008_hw_compute_pll_control` /
//! `ar9160_hw_compute_pll_control`), `ar5008_phy.c::ar5008_hw_process_ini`
//! (ADDAC with `eeprom_def.c::ath9k_hw_def_set_addac`, modes, common,
//! `BB_RfGain`, `ar5008_hw_override_ini`, `ar5008_hw_set_channel_regs`,
//! `ar5008_hw_init_chain_masks`, `ar5008_hw_set_rf_regs` analog banks 0..7),
//! `ar5008_hw_set_rfmode`, `ar5008_hw_set_delta_slope`,
//! `ar5008_hw_spur_mitigate`, the non-AR9280 branches of
//! `eeprom_def.c::ath9k_hw_def_set_board_values` and `ar5008_hw_set_channel`
//! (with `ar5008_hw_force_bias` on AR5416).
//!
//! Register preparation only: no transmit budget is granted and no device
//! is admitted. TX power (`ath9k_hw_apply_txpower`, which Linux runs inside
//! `process_ini` before the analog banks) is the separate power plan.
//! Open-loop maps (`EEP_OL_PWRCTRL`) are refused.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    ar9280,
    channel::{self, Tune},
    rmw, table,
};
use crate::ath9k::{
    chips::{Chip, Revision, MAP_DEF},
    identity::{eeprom_dword, eeprom_word, BringUpError, Identity, RegisterIo},
    initvals_ar5008::*,
};

/// `hw.h::AR5416_DEVID_PCI`, `AR5416_DEVID_PCIE` (AR5418), `AR9160_DEVID_PCI`.
pub(in crate::ath9k) const DEVID_AR5416_PCI: u16 = 0x0023;
pub(in crate::ath9k) const DEVID_AR5416_PCIE: u16 = 0x0024;
pub(in crate::ath9k) const DEVID_AR9160_PCI: u16 = 0x0027;

use ar9280::{MODAL_2G, MODAL_5G};
/// `offsetof(struct modal_eep_header, spurChans)` / `xpaBiasLvlFreq`.
const SPUR_CHANS: usize = 84;
const XPA_BIAS_LVL_FREQ: usize = 72;
/// `AR_PHY(0x37)`: the AR2133/AR5133 synthesizer word.
const AR_PHY_37: u64 = 0x98dc;
/// `ar9002_initvals` row indices `ath9k_hw_def_set_addac` patches (5 GHz /
/// 2 GHz) and the CLKDRV row cleared below AR5416 2.2.
const ADDAC_ROW_5G: usize = 6;
const ADDAC_ROW_2G: usize = 7;
const ADDAC_ROW_CLKDRV: usize = 31;

/// The `ar9002_hw_init_mode_regs` tables for one AR5008-PHY revision.
pub(in crate::ath9k) struct Tables {
    pub modes: &'static [[u32; 5]],
    pub common: &'static [[u32; 2]],
    pub addac: &'static [[u32; 2]],
    pub bank6: &'static [[u32; 3]],
    /// `!AR_SREV_5416_22_OR_LATER`: `INI_RA(addac, 31, 1) = 0`.
    pub clkdrv_off: bool,
}

/// `ar9002_hw.c::ar9002_hw_init_mode_regs` for the AR5008-PHY parts.
pub(in crate::ath9k) fn tables(revision: &Revision) -> Option<Tables> {
    match revision.chip {
        // AR_SREV_9160_10_OR_LATER; AR_SREV_9160_11 is macRev 1.
        Chip::Ar9160 => Some(Tables {
            modes: AR5416_MODES_9160,
            common: AR5416_COMMON_9160,
            addac: if revision.mac_rev == 1 {
                AR5416_ADDAC_9160_1_1
            } else {
                AR5416_ADDAC_9160
            },
            bank6: AR5416_BANK6_TPC_9100,
            clkdrv_off: false,
        }),
        Chip::Ar5416 => Some(Tables {
            modes: AR5416_MODES,
            common: AR5416_COMMON,
            addac: AR5416_ADDAC,
            bank6: AR5416_BANK6_TPC,
            clkdrv_off: revision.mac_rev < 2,
        }),
        _ => None,
    }
}

/// The device's `ah->iniAddac` copy: Linux duplicates the table once at
/// attach (`ar9002_hw_init_mode_regs`) and `ath9k_hw_def_set_addac`
/// rewrites rows 6 (5 GHz) and 7 (2 GHz) in place on every AR9160 reset, so
/// a band change keeps the other band's patched row. The owner retains this
/// for the device's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Addac {
    rows: [u32; 2],
}

impl Addac {
    pub fn new(tables: &Tables) -> Self {
        Self {
            rows: [tables.addac[ADDAC_ROW_5G][1], tables.addac[ADDAC_ROW_2G][1]],
        }
    }

    /// `ath9k_hw_def_set_addac`: AR9160 (`macVersion == 0x40`) with EEPROM
    /// minor >= 7 only. A `xpaBiasLvl` of 0xff selects the
    /// `xpaBiasLvlFreq` bin at or below the center (`FREQ2FBIN`); the
    /// unmasked `biaslevel << 3` / `<< 6` OR is Linux's.
    fn set(&mut self, chip: Chip, identity: &Identity, image: &[u8], tune: Tune) {
        if chip != Chip::Ar9160 || ar9280::minor(identity) < 7 {
            return;
        }
        let five = tune.is_5ghz();
        let base = if five { MODAL_5G } else { MODAL_2G };
        let bias = if image[base + 49] != 0xff {
            image[base + 49]
        } else {
            let center = tune.center();
            let reset_bin = if five {
                (center - 4800) / 5
            } else {
                center - 2300
            };
            let freq = |n: usize| eeprom_word(image, base + XPA_BIAS_LVL_FREQ + 2 * n);
            let mut bias = (freq(0) >> 14) as u8;
            for n in 1..3 {
                if freq(n) == 0 {
                    break;
                }
                if reset_bin >= freq(n) & 0xff {
                    bias = (freq(n) >> 14) as u8;
                } else {
                    break;
                }
            }
            bias
        };
        let bias = u32::from(bias);
        if five {
            self.rows[0] = (self.rows[0] & !0xc0) | (bias << 6);
        } else {
            self.rows[1] = (self.rows[1] & !0x18) | (bias << 3);
        }
    }

    fn value(&self, tables: &Tables, row: usize) -> u32 {
        match row {
            ADDAC_ROW_5G => self.rows[0],
            ADDAC_ROW_2G => self.rows[1],
            ADDAC_ROW_CLKDRV if tables.clkdrv_off => 0,
            _ => tables.addac[row][1],
        }
    }
}

/// `hw.c::ath9k_hw_reverse_bits`.
pub(in crate::ath9k) fn reverse_bits(mut value: u32, bits: u32) -> u32 {
    let mut out = 0;
    for _ in 0..bits {
        out = (out << 1) | (value & 1);
        value >>= 1;
    }
    out
}

/// `ar5008_hw_phy_modify_rx_buffer`: analog swizzle of `bits` (reversed)
/// into the Bank 6 column bytes starting at 1-based `first_bit`.
pub(in crate::ath9k) fn modify_rx_buffer(
    buffer: &mut [u32],
    value: u32,
    bits: u32,
    first_bit: u32,
    column: u32,
) {
    let mut tmp = reverse_bits(value, bits);
    let mut entry = ((first_bit - 1) / 8) as usize;
    let mut position = ((first_bit - 1) % 8) as i32;
    let mut left = bits as i32;
    while left > 0 {
        let last = if position + left > 8 {
            8
        } else {
            position + left
        };
        let mask = (((1u32 << last) - 1) ^ ((1u32 << position) - 1)) << (column * 8);
        buffer[entry] &= !mask;
        buffer[entry] |= ((tmp << position) << (column * 8)) & mask;
        left -= 8 - position;
        tmp >>= 8 - position;
        position = 0;
        entry += 1;
    }
}

/// `ar5008_hw_set_channel`'s `AR_PHY(0x37)` word for a 20 MHz center.
pub(in crate::ath9k) fn synth(chip: Chip, frequency: u16) -> Result<u32, BringUpError> {
    let freq = u32::from(frequency);
    let (select, reference, b_mode) = if freq < 4800 {
        let (select, b_mode) = if (freq - 2192) % 5 == 0 {
            (((freq - 672) * 2 - 3040) / 10, 0)
        } else if (freq - 2224) % 5 == 0 {
            (((freq - 704) * 2 - 3040) / 10, 1)
        } else {
            return Err(BringUpError::Policy);
        };
        (reverse_bits((select << 2) & 0xff, 8), 0, b_mode)
    } else if freq % 20 == 0 && freq >= 5120 {
        (
            reverse_bits(((freq - 4800) / 20) << 2, 8),
            reverse_bits(1, 2),
            0,
        )
    } else if freq % 10 == 0 {
        // AR_SREV_9100 || AR_SREV_9160_10_OR_LATER selects refsel 2.
        let reference = if chip == Chip::Ar9160 { 2 } else { 1 };
        (
            reverse_bits(((freq - 4800) / 10) << 1, 8),
            reverse_bits(reference, 2),
            0,
        )
    } else if freq % 5 == 0 {
        (reverse_bits((freq - 4800) / 5, 8), reverse_bits(1, 2), 0)
    } else {
        return Err(BringUpError::Policy);
    };
    Ok((select << 8) | (reference << 2) | (b_mode << 1) | (1 << 5) | 1)
}

/// `AR_RTC_PLL_CONTROL` for a full-rate channel.
pub(in crate::ath9k) fn pll(chip: Chip, five: bool) -> u32 {
    if chip == Chip::Ar9160 {
        // ar9160_hw_compute_pll_control: REFDIV 5, DIV 0x50 / 0x58.
        (5 << 10) | if five { 0x50 } else { 0x58 }
    } else {
        // ar5008_hw_compute_pll_control: REFDIV_5 | DIV2 | DIV 0xa / 0xb.
        0xc0 | 0x20 | if five { 0xa } else { 0xb }
    }
}

/// The tune for `frequency` when the map's `opCapFlags` enable its band.
/// The AR5008 PHY has no `ATH9K_HW_CAP_FASTCLOCK` and no fractional 5 GHz
/// synthesizer, so `frac_n` is always false.
pub(in crate::ath9k) fn tune(
    identity: &Identity,
    image: &[u8],
    frequency: u16,
) -> Result<Tune, BringUpError> {
    Ok(match ar9280::tune(identity, image, frequency)? {
        Tune::Five { frequency, .. } => Tune::Five {
            frequency,
            frac_n: false,
        },
        two => two,
    })
}

/// `ar5008_hw_set_rf_regs` + `ar5008_hw_set_channel`'s Bank 6 cache
/// (`ah->analogBank6Data`): the INI column with EEPROM minor >= 2 OB/DB
/// swizzled in (`EEP_OB_2`/`EEP_DB_2` at bits 197/194, `EEP_OB_5`/`EEP_DB_5`
/// at 203/200).
pub(in crate::ath9k) fn bank6(
    tables: &Tables,
    identity: &Identity,
    image: &[u8],
    five: bool,
) -> alloc::vec::Vec<u32> {
    let column = if five { 1 } else { 2 };
    let mut data: alloc::vec::Vec<u32> = tables.bank6.iter().map(|row| row[column]).collect();
    if ar9280::minor(identity) >= 2 {
        let base = if five { MODAL_5G } else { MODAL_2G };
        let (ob, db) = (u32::from(image[base + 47]), u32::from(image[base + 48]));
        let (ob_bit, db_bit) = if five { (203, 200) } else { (197, 194) };
        modify_rx_buffer(&mut data, ob, 3, ob_bit, 0);
        modify_rx_buffer(&mut data, db, 3, db_bit, 0);
    }
    data
}

fn write_bank6(io: &mut impl RegisterIo, tables: &Tables, data: &[u32], writes: &mut u16) {
    for (row, value) in tables.bank6.iter().zip(data) {
        table(io, &[[row[0], *value]], 1, writes);
    }
}

/// `ar5008_hw_spur_mitigate`: the first `modalHeader[is2GHz].spurChans`
/// entry within +-9.5 MHz of the center (units of 100 kHz).
fn spur(io: &mut impl RegisterIo, image: &[u8], tune: Tune) -> Result<(), BringUpError> {
    let base = if tune.is_5ghz() { MODAL_5G } else { MODAL_2G };
    let center = i32::from(tune.center());
    let mut selected = None;
    for index in 0..5 {
        let value = eeprom_word(image, base + SPUR_CHANS + index * 4);
        if value == 0x8000 {
            break;
        }
        let offset = i32::from(value) - center * 10;
        if offset > -95 && offset < 95 {
            selected = Some(offset);
            break;
        }
    }
    let Some(bb_spur) = selected else {
        return Ok(());
    };
    // TIMING_CTRL4(0): ENABLE_SPUR_RSSI | SPUR_FILTER | CHAN_MASK | PILOT_MASK.
    rmw(io, 0x9920, 0, 0xf000_0000)?;
    // AR_PHY_SPUR_REG: MASK_RATE_CNTL | ENABLE_MASK_PPM | MASK_RATE_SELECT |
    // ENABLE_VIT_SPUR_RSSI | SPUR_RSSI_THRESH 40.
    channel::write(
        io,
        0x994c,
        (0xff << 18) | 0x20000 | (0xff << 9) | 0x100 | 40,
    )?;
    let phase = ((bb_spur * 524288) / 100) as u32 & 0xfffff;
    let denominator = if tune.is_5ghz() { 400 } else { 440 };
    let sd = ((bb_spur * 2048) / denominator) as u32 & 0x3ff;
    // AR_PHY_TIMING11: USE_SPUR_IN_AGC | SPUR_FREQ_SD | SPUR_DELTA_PHASE.
    channel::write(io, 0x99a0, 0x4000_0000 | (sd << 20) | phase)?;
    channel::masks(io, bb_spur * 32)
}

/// The non-AR9280 `eeprom_def.c::ath9k_hw_def_set_board_values` /
/// `ath9k_hw_def_set_gain`: all three `AR5416_MAX_CHAINS` chains (Linux
/// does not stop at the chain mask), `regChainOffset` swapping chains 1/2
/// when either mask is 0x5, `BSW_MARGIN`/`BSW_ATTEN` (minor >= 3),
/// `AR_PHY_RXGAIN_TXRX_ATTEN` and `AR_PHY_GAIN_2GHZ_RXTX_MARGIN`, PGA
/// desired size and the AR5416 `THRESH62` fields. OB/DB are in Bank 6.
pub(in crate::ath9k) fn set_board_values(
    io: &mut impl RegisterIo,
    identity: &Identity,
    image: &[u8],
    five: bool,
    ht40: bool,
) -> Result<(), BringUpError> {
    if image.len() != MAP_DEF.bytes() {
        return Err(BringUpError::BadLength);
    }
    let minor = ar9280::minor(identity);
    let base = if five { MODAL_5G } else { MODAL_2G };
    let modal = |offset: usize| image[base + offset];
    fn field(
        io: &mut impl RegisterIo,
        register: u64,
        mask: u32,
        shift: u32,
        value: u8,
    ) -> Result<(), BringUpError> {
        channel::field(io, register, mask, shift, u32::from(value))
    }
    io.write32(0x9964, eeprom_dword(image, base + 12) & 0xffff);
    let swap = identity.rx_chainmask == 5 || identity.tx_chainmask == 5;
    for chain in 0..3usize {
        let offset = match chain {
            1 if swap => 0x2000,
            2 if swap => 0x1000,
            _ => chain as u64 * 0x1000,
        };
        io.write32(0x9960 + offset, eeprom_dword(image, base + chain * 4));
        let i = (u32::from(modal(40 + chain)) << 5) & 0x7e0;
        let q = u32::from(modal(43 + chain)) & 0x1f;
        rmw(io, 0x9920 + offset, 0x7e0 | 0x1f, i | q)?;
        let mut atten = if five { 44 } else { 23 };
        if minor >= 3 {
            atten = modal(20 + chain);
            // AR_PHY_GAIN_2GHZ BSW_MARGIN (0x3c00) / BSW_ATTEN (0x1f).
            field(io, 0xa20c + offset, 0x3c00, 10, modal(58 + chain))?;
            field(io, 0xa20c + offset, 0x1f, 0, modal(55 + chain))?;
        }
        // AR_PHY_RXGAIN TXRX_ATTEN (0x3f000), AR_PHY_GAIN_2GHZ RXTX_MARGIN.
        field(io, 0x9848 + offset, 0x0003_f000, 12, atten)?;
        field(io, 0xa20c + offset, 0x00fc_0000, 18, modal(23 + chain))?;
    }
    field(io, 0x9844, 0x0000_3f80, 7, modal(19))?; // AR_PHY_SETTLING_SWITCH.
    field(io, 0x9850, 0xff, 0, modal(26))?; // AR_PHY_DESIRED_SZ_ADC.
    field(io, 0x9850, 0xff00, 8, modal(27))?; // AR_PHY_DESIRED_SZ_PGA.
    let (xpa_off, xpa_on) = (u32::from(modal(31)), u32::from(modal(33)));
    io.write32(
        0x9834,
        (xpa_off << 24) | (xpa_off << 16) | (xpa_on << 8) | xpa_on,
    );
    field(io, 0x9828, 0x00ff_0000, 16, modal(32))?; // TX_END_TO_A2_RX_ON.
    field(io, 0x9864, 0x0007_f000, 12, modal(34))?; // AR_PHY_CCA_THRESH62.
    field(io, 0x99bc, 0x007f_0000, 16, modal(34))?; // AR_PHY_EXT_CCA_THRESH62.
    if minor >= 2 {
        field(io, 0x9824, 0xff, 0, modal(52))?; // TX_END_DATA_START.
        field(io, 0x9824, 0xff00, 8, modal(53))?; // TX_END_PA_ON.
    }
    if minor >= 3 && ht40 {
        field(io, 0x9844, 0x0000_3f80, 7, modal(61))?;
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Prepared {
    pub tune: Tune,
    /// `ar5008_hw_process_ini`'s `regWrites`: ADDAC, modes, common and
    /// `BB_RfGain` rows.
    pub ini_writes: u16,
}

/// The `process_ini` row count (channel-independent within a band).
pub(in crate::ath9k) fn ini_rows(tables: &Tables) -> u16 {
    (tables.addac.len() + tables.modes.len() + tables.common.len() + AR5416_BB_RF_GAIN.len()) as u16
}

/// Inactive full-reset preparation of one 20 MHz channel in either band on
/// an AR5416/AR5418 (`0x0023`/`0x0024`) or AR9160 (`0x0027`). `addac` is the
/// device's retained ADDAC copy (see [`Addac`]). PHY, interrupts and packet
/// engines stay off.
pub(in crate::ath9k) fn prepare(
    io: &mut impl RegisterIo,
    revision: &Revision,
    identity: &Identity,
    image: &[u8],
    device: u16,
    frequency: u16,
    addac: &mut Addac,
) -> Result<Prepared, BringUpError> {
    let device_chip = match device {
        DEVID_AR5416_PCI | DEVID_AR5416_PCIE => Chip::Ar5416,
        DEVID_AR9160_PCI => Chip::Ar9160,
        _ => return Err(BringUpError::UnsupportedRevision),
    };
    let tables = match tables(revision) {
        Some(tables) if revision.chip == device_chip => tables,
        _ => return Err(BringUpError::UnsupportedRevision),
    };
    let tune = tune(identity, image, frequency)?;
    if ar9280::open_loop(identity, image) {
        return Err(BringUpError::BadCalibration);
    }
    let five = tune.is_5ghz();
    let synth = synth(revision.chip, frequency)?;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(0x24, 0); // AR_IER_DISABLE.
    io.write32(0x880, 0x3ff); // Disable all ten TX queues.
    io.write32(0x8, 0x20); // AR_CR_RXD, never RXE.
    rmw(io, 0x8048, 0, 0x0200_0020)?; // RX_ABORT | RX_DIS.
    io.write32(0x981c, 0); // AR_PHY_ACTIVE_DIS.
    io.write32(0x7014, pll(revision.chip, five));
    io.delay_us(100); // RTC_PLL_SETTLE_DELAY.
    io.write32(0x7048, 2); // AR_RTC_FORCE_DERIVED_CLK.

    // ar5008_hw_process_ini: freqIndex 1 (5 GHz) / 2 (2 GHz); modesIndex
    // 1 (5 GHz HT20) / 4 (2 GHz HT20).
    let (freq_index, modes_index) = if five { (1, 1) } else { (2, 4) };
    io.write32(0x9800, 7); // AR_PHY(0): analog shift.
    io.write32(0x9830, 1); // AR_PHY_SEL_EXTERNAL_RADIO.
    addac.set(revision.chip, identity, image, tune);
    let mut writes = 0;
    for (index, row) in tables.addac.iter().enumerate() {
        table(io, &[[row[0], addac.value(&tables, index)]], 1, &mut writes);
    }
    io.write32(0x9830, 0); // AR_PHY_SEL_INTERNAL_ADDAC.
    table(io, tables.modes, modes_index, &mut writes);
    table(io, tables.common, 1, &mut writes);
    table(io, AR5416_BB_RF_GAIN, freq_index, &mut writes);

    // ar5008_hw_override_ini: no MISC_MODE2 below AR9280; BB clock gating
    // off (`0x9800 + (651 << 2)`); AR9160 RIFS search off.
    rmw(io, 0x8048, 0, 0x0200_0020)?;
    channel::write(io, 0x9e2c, 0x11)?;
    if revision.chip == Chip::Ar9160 {
        rmw(io, 0x99ec, 0x03ff_0000, 0)?; // AR_PHY_RIFS_INIT_DELAY.
    }
    // ar5008_hw_set_channel_regs (HT20): HT_EN | SHORT_GI_40 |
    // SINGLE_HT_LTF1 | WALSH, AR_2040_MODE 0, GTXTO, CST.
    channel::write(io, 0x9804, 0x3c0)?;
    channel::write(io, 0x8318, 0)?;
    channel::write(io, 0x64, 25 << 16)?;
    channel::write(io, 0x6c, 15 << 16)?;
    // ar5008_hw_init_chain_masks: masks 1/2/3/5/7 program RX/CAL (0x5
    // first sets AR_PHY_SWAP_ALT_CHAIN); any other RX mask leaves them.
    let (rx, tx) = (identity.rx_chainmask, identity.tx_chainmask);
    if rx == 5 {
        rmw(io, 0xa268, 0, 0x40)?;
    }
    if matches!(rx, 1 | 2 | 3 | 5 | 7) {
        channel::write(io, 0x99a4, u32::from(rx))?;
        channel::write(io, 0xa39c, u32::from(rx))?;
    }
    channel::write(io, 0x832c, u32::from(tx))?;
    if tx == 5 {
        rmw(io, 0xa268, 0, 0x40)?;
    }
    // ar5008_hw_set_rf_regs(freqIndex): banks 0, 1, 2, 3, 6, 7.
    let mut data = bank6(&tables, identity, image, five);
    let mut rf_writes = 0;
    table(io, AR5416_BANK0, 1, &mut rf_writes);
    table(io, AR5416_BANK1, 1, &mut rf_writes);
    table(io, AR5416_BANK2, 1, &mut rf_writes);
    table(io, AR5416_BANK3, freq_index, &mut rf_writes);
    write_bank6(io, &tables, &data, &mut rf_writes);
    table(io, AR5416_BANK7, 1, &mut rf_writes);

    // ar5008_hw_set_rfmode: 2 GHz DYNAMIC | RF2GHZ, 5 GHz OFDM | RF5GHZ.
    channel::write(io, 0xa200, if five { 0 } else { 6 })?;
    // ar5008_hw_set_delta_slope (full rate, synth center).
    let coefficient = 0x6400_0000 / u32::from(frequency);
    let (mantissa, exponent) = channel::slope(coefficient);
    channel::field(io, 0x9814, 0xfffe_0000, 17, mantissa)?;
    channel::field(io, 0x9814, 0x1e000, 13, exponent)?;
    let (mantissa, exponent) = channel::slope(9 * coefficient / 10);
    channel::field(io, 0x99d0, 0x7fff0, 4, mantissa)?;
    channel::field(io, 0x99d0, 15, 0, exponent)?;
    spur(io, image, tune)?;
    set_board_values(io, identity, image, five, false)?;
    // ar5008_hw_set_channel: CCK Japan bit off (2484 is never a tune here),
    // AR5416 force bias, then the synthesizer word.
    if !five {
        rmw(io, 0xa204, 0x10, 0)?;
        if revision.chip == Chip::Ar5416 {
            // ar5008_hw_force_bias: rf_pwd_icsyndiv 0 / 1 / 2, pre-reversed.
            let bias = if frequency < 2412 {
                0
            } else if frequency < 2422 {
                1
            } else {
                2
            };
            modify_rx_buffer(&mut data, reverse_bits(bias, 3), 3, 181, 3);
            let mut bias_writes = 0;
            write_bank6(io, &tables, &data, &mut bias_writes);
        }
    }
    channel::write(io, AR_PHY_37, synth)?;
    io.write32(0x981c, 0);
    io.write32(0x24, 0);
    io.write32(0x8, 0x20);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(Prepared {
        tune,
        ini_writes: writes,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
