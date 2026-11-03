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
//! AR9287 (AR9002, two chains, 2.4 GHz only) inactive 20 MHz baseband
//! preparation: `ar5008_phy.c::ar5008_hw_process_ini` with the
//! `ar9002_hw.c` AR9287 1.1+ table selection, the shared AR9002 channel
//! preparation with the two-chain mask and CCK FIR differences, and
//! `eeprom_9287.c::ath9k_hw_ar9287_set_board_values`.
//!
//! Open-loop/closed-loop transmit power (`ath9k_hw_ar9287_set_txpower`,
//! `ath9k_olc_init`) and AR9287 calibration are not part of this stage, so
//! the result is register preparation only: it grants no transmit budget and
//! no device is admitted by it.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    channel::{self, ChipChannel},
    rmw, table,
};
use crate::ath9k::{
    channel_width::Geometry,
    chips::{Chip, Revision, MAP_9287},
    identity::{eeprom_dword, BringUpError, Identity, RegisterIo},
    initvals_ar9287::*,
};

/// `offsetof(struct ar9287_eeprom, modalHeader)`.
const MODAL: usize = 96;
/// `offsetof(struct modal_eep_ar9287_header, spurChans)`.
const SPUR_CHANS: usize = MODAL + 79;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Prepared {
    pub geometry: Geometry,
    pub ini_writes: u16,
}

/// `ar9002_phy.c::ar9002_hw_set_channel`: channel 14 enables CCK channel
/// spreading through the Japan FIR coefficients on AR9287 1.1+.
pub(in crate::ath9k) fn cck_fir(frequency: u16) -> &'static [[u32; 2]] {
    if frequency == 2484 {
        AR9287_COMMON_JAPAN_2484_CCK_FIR_COEFF_9287_1_1
    } else {
        AR9287_COMMON_NORMAL_CCK_FIR_COEFF_9287_1_1
    }
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

/// `eeprom.c::ath9k_hw_analog_shift_regwrite` / `_rmw`: PCI sets
/// `config.analog_shiftreg`, so every analog write settles for 100 us.
fn analog_rmw(
    io: &mut impl RegisterIo,
    register: u64,
    mask: u32,
    set: u32,
) -> Result<(), BringUpError> {
    rmw(io, register, mask, set & mask)?;
    io.delay_us(100);
    Ok(())
}

/// `eeprom_9287.c::ath9k_hw_ar9287_set_board_values` for a 2.4 GHz channel.
/// Multibyte fields follow EEPMISC byte order like Linux's post-swap `le*`.
pub(in crate::ath9k) fn set_board_values(
    io: &mut impl RegisterIo,
    image: &[u8],
    ht40: bool,
) -> Result<(), BringUpError> {
    if image.len() != MAP_9287.bytes() {
        return Err(BringUpError::BadLength);
    }
    let modal = |offset: usize| image[MODAL + offset];
    io.write32(0x9964, eeprom_dword(image, MODAL + 8)); // AR_PHY_SWITCH_COM.
    for chain in 0..2usize {
        let offset = chain as u64 * 0x1000;
        io.write32(0x9960 + offset, eeprom_dword(image, MODAL + chain * 4));
        // AR_PHY_TIMING_CTRL4: IQCORR_Q_I_COFF (0x7e0) / Q_Q_COFF (0x1f).
        let i = (u32::from(modal(28 + chain)) << 5) & 0x7e0;
        let q = u32::from(modal(30 + chain)) & 0x1f;
        rmw(io, 0x9920 + offset, 0x7e0 | 0x1f, i | q)?;
        // AR_PHY_GAIN_2GHZ XATTEN1_MARGIN / XATTEN1_DB.
        field(io, 0xa20c + offset, 0x0001_f000, 12, modal(39 + chain))?;
        field(io, 0xa20c + offset, 0x0000_003f, 0, modal(37 + chain))?;
        // AR_PHY_RXGAIN AR9280_PHY_RXGAIN_TXRX_ATTEN / _MARGIN.
        field(io, 0x9848 + offset, 0x0000_3f80, 7, modal(15 + chain))?;
        field(io, 0x9848 + offset, 0x001f_c000, 14, modal(17 + chain))?;
    }
    let settle = if ht40 { modal(41) } else { modal(14) };
    field(io, 0x9844, 0x0000_3f80, 7, settle)?; // AR_PHY_SETTLING_SWITCH.
    field(io, 0x9850, 0xff, 0, modal(19))?; // AR_PHY_DESIRED_SZ_ADC.
    let (xpa_off, xpa_on) = (u32::from(modal(20)), u32::from(modal(22)));
    io.write32(
        0x9834, // AR_PHY_RF_CTL4: XPAA/XPAB off and on.
        (xpa_off << 24) | (xpa_off << 16) | (xpa_on << 8) | xpa_on,
    );
    field(io, 0x9828, 0x00ff_0000, 16, modal(21))?; // TX_END_TO_A2_RX_ON.
    field(io, 0x9864, 0x000f_f000, 12, modal(23))?; // AR9280 CCA THRESH62.
    field(io, 0x99b8, 0xff, 0, modal(23))?; // AR_PHY_EXT_CCA0_THRESH62.
                                            // AR9287_AN_RF2G3_CH0/CH1: DB1, DB2, OB_CCK, OB_PSK, OB_QAM, OB_PAL_OFF.
    let rf2g3 = (u32::from(modal(43) & 7) << 29)
        | (u32::from(modal(44) & 7) << 26)
        | (u32::from(modal(45) & 7) << 23)
        | (u32::from(modal(46) & 7) << 20)
        | (u32::from(modal(47) & 7) << 17)
        | (u32::from(modal(48) & 7) << 14);
    for register in [0x7808, 0x785c] {
        analog_rmw(io, register, 0xffff_c000, rf2g3)?;
    }
    field(io, 0x9824, 0xff, 0, modal(34))?; // TX_END_DATA_START.
    field(io, 0x9824, 0xff00, 8, modal(35))?; // TX_END_PA_ON.
                                              // AR9287_AN_TOP2_XPABIAS_LVL.
    analog_rmw(io, 0x78b4, 0xc000_0000, u32::from(modal(33)) << 30)?;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

/// Inactive full-reset INI, channel and board-value preparation for one
/// 20 MHz 2.4 GHz channel. PHY, interrupts and packet engines stay off.
pub(in crate::ath9k) fn prepare(
    io: &mut impl RegisterIo,
    revision: &Revision,
    identity: &Identity,
    image: &[u8],
    frequency: u16,
) -> Result<Prepared, BringUpError> {
    // `ar9002_hw_init_mode_regs` has tables only for AR_SREV_9287_11_OR_LATER.
    if revision.chip != Chip::Ar9287 || revision.mac_rev < 1 {
        return Err(BringUpError::UnsupportedRevision);
    }
    if image.len() != MAP_9287.bytes() {
        return Err(BringUpError::BadLength);
    }
    let geometry = Geometry::from_frequency(frequency)?;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(0x24, 0); // AR_IER_DISABLE.
    io.write32(0x880, 0x3ff); // Disable all ten TX queues.
    io.write32(0x8, 0x20); // AR_CR_RXD, never RXE.
    rmw(io, 0x8048, 0, 0x0200_0020)?; // RX_ABORT | RX_DIS.
    io.write32(0x981c, 0); // AR_PHY_ACTIVE_DIS.
                           // ar9002_hw_compute_pll_control (AR9280_20_OR_LATER, 2 GHz full rate).
    io.write32(0x7014, (5 << 10) | 0x2c);
    io.delay_us(100);
    io.write32(0x7048, 2); // AR_RTC_FORCE_DERIVED_CLK.
    io.write32(0x9800, 7);
    io.write32(0x9830, 1); // AR_PHY_SEL_EXTERNAL_RADIO.
    io.write32(0x9830, 0); // No AR9287 ADDAC table or set_addac op.
    let mut writes = 0;
    // modesIndex 4: 2 GHz HT20 (`ar5008_hw_process_ini`).
    table(io, AR9287_MODES_9287_1_1, 4, &mut writes);
    table(io, AR9287_MODES_RX_GAIN_9287_1_1, 4, &mut writes);
    table(io, AR9287_MODES_TX_GAIN_9287_1_1, 4, &mut writes);
    table(io, AR9287_COMMON_9287_1_1, 1, &mut writes);
    let chip = ChipChannel {
        misc_mode2_clear: 0x40 | 0x10_0000 | 0x200_0000,
        rx_chainmask: identity.rx_chainmask,
        tx_chainmask: identity.tx_chainmask,
        cck_fir: Some(cck_fir),
        spur_chans: SPUR_CHANS,
    };
    channel::prepare_chip(io, image, geometry, &chip)?;
    set_board_values(io, image, false)?;
    io.write32(0x981c, 0);
    io.write32(0x24, 0);
    io.write32(0x8, 0x20);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(Prepared {
        geometry,
        ini_writes: writes,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;

/// `ath9k_hw_ar9287_set_txpower` (open-loop, 20 MHz).
pub(in crate::ath9k) mod power;
