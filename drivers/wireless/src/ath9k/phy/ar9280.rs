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
//! AR9280 2.0 (AR9002, two chains, dual band) inactive 20 MHz baseband
//! preparation: `ar5008_phy.c::ar5008_hw_process_ini` with the
//! `ar9002_hw.c` AR9280_2 table selection (modes, EEPROM-selected RX/TX
//! gain, common, 5 GHz fast clock), the shared AR9002 channel preparation
//! for 2.4 GHz and 5 GHz (`ar9002_phy.c::ar9002_hw_set_channel`,
//! `ar9002_hw_spur_mitigate`) and `eeprom_def.c::ath9k_hw_def_set_board_values`.
//!
//! This is register preparation only: it grants no transmit budget and no
//! device is admitted by it. Open-loop maps (`EEP_OL_PWRCTRL`) are refused:
//! this port follows the closed-loop `eeprom_def.c` PDADC path only.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    channel::{self, ChipChannel, Tune},
    rmw, table,
};
use crate::ath9k::{
    channel_width::Geometry,
    chips::{Chip, Revision, MAP_DEF},
    identity::{eeprom_dword, BringUpError, Identity, RegisterIo},
    initvals_ar9280::*,
};

/// `hw.h::AR9280_DEVID_PCI`; `AR9280_DEVID_PCIE` is `0x002a`.
pub(in crate::ath9k) const DEVID_PCI: u16 = 0x0029;
pub(in crate::ath9k) const DEVID_PCIE: u16 = 0x002a;

/// `offsetof(struct ar5416_eeprom_def, modalHeader[0])` (5 GHz) and
/// `modalHeader[1]` (2 GHz); each `modal_eep_header` is 104 bytes.
pub(in crate::ath9k) const MODAL_5G: usize = 128;
pub(in crate::ath9k) const MODAL_2G: usize = 232;
/// `offsetof(struct modal_eep_header, spurChans)`.
const SPUR_CHANS: usize = 84;

/// `base_eep_header` byte offsets.
const OP_CAP_FLAGS: usize = 6;
const PWDCLKIND: usize = 31;
const RX_GAIN_TYPE: usize = 34;
const DAC_HI_PWR_MODE_5G: usize = 35;
const OPEN_LOOP_PWR_CNTL: usize = 36;
const DAC_LP_MODE: usize = 37;
const TX_GAIN_TYPE: usize = 38;
const DESIRED_SCALE_CCK: usize = 40;
const FRAC_N_5G: usize = 42;

/// `eeprom.h::AR5416_OPFLAGS_11A` / `_11G`.
const OPFLAGS_11A: u8 = 0x01;
const OPFLAGS_11G: u8 = 0x02;

/// `ath9k_hw_def_get_eeprom_rev`: the minor version.
pub(in crate::ath9k) fn minor(identity: &Identity) -> u16 {
    identity.eeprom_version & 0xfff
}

/// `ath9k_hw_def_get_eeprom(EEP_OL_PWRCTRL)`: from minor 19 only.
pub(in crate::ath9k) fn open_loop(identity: &Identity, image: &[u8]) -> bool {
    minor(identity) >= 0x13 && image[OPEN_LOOP_PWR_CNTL] != 0
}

/// The 20 MHz 5 GHz channels this port tunes: UNII-1/2 (36..64), UNII-2e
/// (100..144) and UNII-3 (149..165). Regulatory admission (DFS / NO_IR) is
/// separate.
pub(in crate::ath9k) fn channel_5ghz(frequency: u16) -> Option<u8> {
    let channel = frequency.checked_sub(5000)? / 5;
    let valid = frequency % 5 == 0
        && matches!(channel, 36..=64 | 100..=144 | 149..=165)
        && channel % 4 == if channel >= 149 { 1 } else { 0 };
    valid.then_some(channel as u8)
}

/// `ar9002_hw.c::ar9280_20_hw_init_rxgain_ini`.
pub(in crate::ath9k) fn rx_gain(identity: &Identity, image: &[u8]) -> &'static [[u32; 5]] {
    if minor(identity) >= 0x11 {
        match image[RX_GAIN_TYPE] {
            1 => return AR9280_MODES_BACKOFF_13DB_RXGAIN_9280_2,
            0 => return AR9280_MODES_BACKOFF_23DB_RXGAIN_9280_2,
            _ => {}
        }
    }
    AR9280_MODES_ORIGINAL_RXGAIN_9280_2
}

/// `ar9002_hw.c::ar9280_20_hw_init_txgain_ini`.
pub(in crate::ath9k) fn tx_gain(identity: &Identity, image: &[u8]) -> &'static [[u32; 5]] {
    if minor(identity) >= 0x13 && image[TX_GAIN_TYPE] == 1 {
        AR9280_MODES_HIGH_POWER_TX_GAIN_9280_2
    } else {
        AR9280_MODES_ORIGINAL_TX_GAIN_9280_2
    }
}

/// `eeprom_def.c::ath9k_hw_def_check_eeprom`: `need_an_top2_fixup` for the
/// PCI device with minor > 0x0a and `pwdclkind == 0`.
pub(in crate::ath9k) fn an_top2_fixup(device: u16, identity: &Identity, image: &[u8]) -> bool {
    device == DEVID_PCI && identity.eeprom_version & 0xff > 0x0a && image[PWDCLKIND] == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Prepared {
    pub tune: Tune,
    pub ini_writes: u16,
}

fn field(
    io: &mut impl RegisterIo,
    register: u64,
    mask: u32,
    shift: u32,
    value: u8,
) -> Result<(), BringUpError> {
    rmw(io, register, mask, (u32::from(value) << shift) & mask)
}

/// `eeprom.c::ath9k_hw_analog_shift_rmw`: PCI sets `config.analog_shiftreg`,
/// so every analog write settles for 100 us.
fn analog_field(
    io: &mut impl RegisterIo,
    register: u64,
    mask: u32,
    shift: u32,
    value: u8,
) -> Result<(), BringUpError> {
    field(io, register, mask, shift, value)?;
    io.delay_us(100);
    Ok(())
}

/// `eeprom_def.c::ath9k_hw_def_set_board_values` (with
/// `ath9k_hw_def_set_gain`) for AR9280: `modalHeader[IS_CHAN_2GHZ]`, chains
/// 0 and 1 only (`AR_SREV_9280` breaks at `i >= 2`; the factory masks never
/// carry 0x5 so `regChainOffset = i * 0x1000`). Multibyte fields follow
/// EEPMISC byte order like Linux's post-swap `le*`.
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
    let minor = minor(identity);
    let base = if five { MODAL_5G } else { MODAL_2G };
    let modal = |offset: usize| image[base + offset];
    // AR_PHY_SWITCH_COM: antCtrlCommon & 0xffff.
    io.write32(0x9964, eeprom_dword(image, base + 12) & 0xffff);
    for chain in 0..2usize {
        let offset = chain as u64 * 0x1000;
        // AR_PHY_SWITCH_CHAIN_0 + offset: antCtrlChain[i].
        io.write32(0x9960 + offset, eeprom_dword(image, base + chain * 4));
        // AR_PHY_TIMING_CTRL4: IQCORR_Q_I_COFF (0x7e0) / Q_Q_COFF (0x1f).
        let i = (u32::from(modal(40 + chain)) << 5) & 0x7e0;
        let q = u32::from(modal(43 + chain)) & 0x1f;
        rmw(io, 0x9920 + offset, 0x7e0 | 0x1f, i | q)?;
        let mut atten = if five { 44 } else { 23 };
        if minor >= 3 {
            atten = modal(20 + chain);
            // AR_PHY_GAIN_2GHZ: XATTEN1 margin/db from bswMargin/bswAtten,
            // XATTEN2 margin/db.
            field(io, 0xa20c + offset, 0x0001_f000, 12, modal(58 + chain))?;
            field(io, 0xa20c + offset, 0x0000_003f, 0, modal(55 + chain))?;
            field(io, 0xa20c + offset, 0x003e_0000, 17, modal(65 + chain))?;
            field(io, 0xa20c + offset, 0x0000_0fc0, 6, modal(62 + chain))?;
        }
        // AR_PHY_RXGAIN AR9280_PHY_RXGAIN_TXRX_ATTEN / _MARGIN.
        field(io, 0x9848 + offset, 0x0000_3f80, 7, atten)?;
        field(io, 0x9848 + offset, 0x001f_c000, 14, modal(23 + chain))?;
    }
    let (ob, db, ob1, db1) = (modal(47), modal(48), modal(68), modal(69));
    if five {
        // AR_AN_RF5G1_CH0/CH1: OB5 (0x70000) / DB5 (0x380000).
        analog_field(io, 0x7818, 0x0007_0000, 16, ob)?;
        analog_field(io, 0x7818, 0x0038_0000, 19, db)?;
        analog_field(io, 0x783c, 0x0007_0000, 16, ob1)?;
        analog_field(io, 0x783c, 0x0038_0000, 19, db1)?;
    } else {
        // AR_AN_RF2G1_CH0/CH1: OB (0x3800000) / DB (0x1c000000).
        analog_field(io, 0x7810, 0x0380_0000, 23, ob)?;
        analog_field(io, 0x7810, 0x1c00_0000, 26, db)?;
        analog_field(io, 0x7834, 0x0380_0000, 23, ob1)?;
        analog_field(io, 0x7834, 0x1c00_0000, 26, db1)?;
    }
    let lna_ctl = modal(70);
    // AR_AN_TOP2: XPABIAS_LVL, LOCALBIAS (LNA_CTL_LOCAL_BIAS).
    analog_field(io, 0x7894, 0xc000_0000, 30, modal(49))?;
    analog_field(io, 0x7894, 0x0020_0000, 21, u8::from(lna_ctl & 0x20 != 0))?;
    // AR_PHY_XPA_CFG FORCE_XPA_CFG (LNA_CTL_FORCE_XPA).
    field(io, 0xa3d8, 1, 0, u8::from(lna_ctl & 0x40 != 0))?;
    field(io, 0x9844, 0x0000_3f80, 7, modal(19))?; // AR_PHY_SETTLING_SWITCH.
    field(io, 0x9850, 0xff, 0, modal(26))?; // AR_PHY_DESIRED_SZ_ADC.
    let (xpa_off, xpa_on) = (u32::from(modal(31)), u32::from(modal(33)));
    io.write32(
        0x9834, // AR_PHY_RF_CTL4: XPAA/XPAB off and on.
        (xpa_off << 24) | (xpa_off << 16) | (xpa_on << 8) | xpa_on,
    );
    field(io, 0x9828, 0x00ff_0000, 16, modal(32))?; // TX_END_TO_A2_RX_ON.
    field(io, 0x9864, 0x000f_f000, 12, modal(34))?; // AR9280 CCA THRESH62.
    field(io, 0x99b8, 0xff, 0, modal(34))?; // AR_PHY_EXT_CCA0_THRESH62.
    if minor >= 2 {
        field(io, 0x9824, 0xff, 0, modal(52))?; // TX_END_DATA_START.
        field(io, 0x9824, 0xff00, 8, modal(53))?; // TX_END_PA_ON.
    }
    if minor >= 3 && ht40 {
        field(io, 0x9844, 0x0000_3f80, 7, modal(61))?; // swSettleHt40.
    }
    let misc = modal(71);
    if minor >= 0x13 {
        // AR_PHY_CCK_TX_CTRL_TX_DAC_SCALE_CCK.
        field(io, 0xa204, 0x0c, 2, misc)?;
    }
    if minor >= 0x14 {
        // AR_AN_TOP1_DACIPMODE: dacLpMode, or 0 on 5 GHz dacHiPwrMode_5G.
        let mode = if five && image[DAC_HI_PWR_MODE_5G] != 0 {
            0
        } else {
            image[DAC_LP_MODE]
        };
        field(io, 0x7890, 0x0004_0000, 18, mode)?;
        io.delay_us(100);
        field(io, 0x9944, 0x38, 3, misc >> 2)?; // AR_PHY_FRAME_CTL_TX_CLIP.
                                                // AR_PHY_TX_PWRCTRL9 DESIRED_SCALE_CCK.
        field(io, 0xa27c, 0x7c00, 10, image[DESIRED_SCALE_CCK])?;
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

/// The tune for `frequency` if the map enables its band
/// (`AR5416_OPFLAGS_11G` / `_11A`, `hw.c::ath9k_hw_fill_cap_info`).
pub(in crate::ath9k) fn tune(
    identity: &Identity,
    image: &[u8],
    frequency: u16,
) -> Result<Tune, BringUpError> {
    if image.len() != MAP_DEF.bytes() {
        return Err(BringUpError::BadLength);
    }
    let flags = image[OP_CAP_FLAGS];
    if channel_5ghz(frequency).is_some() {
        if flags & OPFLAGS_11A == 0 {
            return Err(BringUpError::Policy);
        }
        let frac_n = minor(identity) >= 0x16 && image[FRAC_N_5G] != 0;
        return Ok(Tune::Five { frequency, frac_n });
    }
    let geometry = Geometry::from_frequency(frequency)?;
    if flags & OPFLAGS_11G == 0 {
        return Err(BringUpError::Policy);
    }
    Ok(Tune::Two(geometry))
}

/// The INI row count for a tune (channel-independent within a band).
pub(in crate::ath9k) fn ini_rows(identity: &Identity, image: &[u8], tune: Tune) -> u16 {
    let fast = if tune.is_5ghz() {
        AR9280_MODES_FAST_CLOCK_9280_2.len()
    } else {
        0
    };
    (AR9280_MODES_9280_2.len()
        + rx_gain(identity, image).len()
        + tx_gain(identity, image).len()
        + AR9280_COMMON_9280_2.len()
        + fast) as u16
}

/// Inactive full-reset INI, channel and board-value preparation for one
/// 20 MHz channel in either band. PHY, interrupts and packet engines stay
/// off. `device` is the PCI device ID (`0x0029` / `0x002a`).
pub(in crate::ath9k) fn prepare(
    io: &mut impl RegisterIo,
    revision: &Revision,
    identity: &Identity,
    image: &[u8],
    device: u16,
    frequency: u16,
) -> Result<Prepared, BringUpError> {
    // `ar9002_hw_init_mode_regs` selects the AR9280_2 tables for every
    // `AR_SREV_9280_20` part (macVersion 0x80, any revision).
    if revision.chip != Chip::Ar9280 || !matches!(device, DEVID_PCI | DEVID_PCIE) {
        return Err(BringUpError::UnsupportedRevision);
    }
    let tune = tune(identity, image, frequency)?;
    if open_loop(identity, image) {
        return Err(BringUpError::BadCalibration);
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(0x24, 0); // AR_IER_DISABLE.
    io.write32(0x880, 0x3ff); // Disable all ten TX queues.
    io.write32(0x8, 0x20); // AR_CR_RXD, never RXE.
    rmw(io, 0x8048, 0, 0x0200_0020)?; // RX_ABORT | RX_DIS.
    io.write32(0x981c, 0); // AR_PHY_ACTIVE_DIS.
                           // ar9002_hw_compute_pll_control: AR9280 always has FASTCLOCK, so
                           // 5 GHz keeps the 2 GHz ref_div 5 / pll_div 0x2c.
    io.write32(0x7014, (5 << 10) | 0x2c);
    io.delay_us(100);
    io.write32(0x7048, 2); // AR_RTC_FORCE_DERIVED_CLK.
    io.write32(0x9800, 7);
    io.write32(0x9830, 1); // AR_PHY_SEL_EXTERNAL_RADIO.
    io.write32(0x9830, 0); // No AR9280 ADDAC table or set_addac op.
    let mut writes = 0;
    // ar5008_hw_process_ini modesIndex: 5 GHz HT20 = 1, 2 GHz HT20 = 4.
    let column = if tune.is_5ghz() { 1 } else { 4 };
    let fixup = an_top2_fixup(device, identity, image);
    for row in AR9280_MODES_9280_2 {
        let mut value = row[column];
        if row[0] == 0x7894 && fixup {
            value &= !0x0040_0000; // AR_AN_TOP2_PWDCLKIND.
        }
        table(io, &[[row[0], value]], 1, &mut writes);
    }
    table(io, rx_gain(identity, image), column, &mut writes);
    table(io, tx_gain(identity, image), column, &mut writes);
    table(io, AR9280_COMMON_9280_2, 1, &mut writes);
    if tune.is_5ghz() {
        // IS_CHAN_A_FAST_CLOCK: the 3-column table at modesIndex 1.
        table(io, AR9280_MODES_FAST_CLOCK_9280_2, 1, &mut writes);
    }
    let chip = ChipChannel {
        misc_mode2_clear: 0x40 | 0x10_0000,
        rx_chainmask: identity.rx_chainmask,
        tx_chainmask: identity.tx_chainmask,
        cck_fir: None,
        spur_chans: MODAL_2G + SPUR_CHANS,
        spur_chans_5g: Some(MODAL_5G + SPUR_CHANS),
    };
    channel::prepare_tune(io, image, tune, &chip)?;
    set_board_values(io, identity, image, tune.is_5ghz(), false)?;
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
