// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_eeprom.c::ath9k_hw_ar9300_set_board_values` for an AR9300 (the
//! `AR_SREV_9300` branch of every helper): xPA timing, xPA bias, antenna
//! switch tables, drive strength, xLNA bias, xatten, quick drop, the
//! RTC internal regulator, crystal tuning caps, minCCApwr thresholds,
//! TX-end-to-xPA-off and the thermometer selection. `thermo_cal` is
//! AR9462-only and the AR9485/AR9330 antenna-diversity GPIOs do not apply.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    eeprom::{field, modal, modal_base},
    field as set_field,
    power::{power_interpolate, Image},
    rmw,
};
use crate::ath9k::identity::{BringUpError, RegisterIo};

const AR_PHY_XPA_TIMING_CTL: u64 = 0xa264;
const AR_CH0_TOP: u64 = 0x16288;
const AR_CH0_THERM: u64 = 0x16290;
const AR_CH0_XTAL: u64 = 0x16294;
const AR_PHY_SWITCH_COM: u64 = 0xa288;
const AR_PHY_SWITCH_COM_2: u64 = 0xa28c;
const SWITCH_CHAIN: [u64; 3] = [0xa284, 0xb284, 0xc284];
const EXT_ATTEN_CTL: [u64; 3] = [0x9e18, 0xae18, 0xbe18];
const CCA_CTRL: [u64; 3] = [0x9e20, 0xae20, 0xbe20];
const RXTX4: [u64; 3] = [0x1610c, 0x1650c, 0x1690c];
const AR_PHY_65NM_CH0_BIAS1: u64 = 0x160c0;
const AR_PHY_65NM_CH0_BIAS2: u64 = 0x160c4;
const AR_PHY_65NM_CH0_BIAS4: u64 = 0x160cc;
const AR_PHY_AGC: u64 = 0x9e14;
const AR_RTC_REG_CONTROL0: u64 = 0x7008;
const AR_RTC_REG_CONTROL1: u64 = 0x700c;
const AR_RTC_SLEEP_CLK: u64 = 0x7048;

fn u16_at(image: &Image, at: usize) -> u32 {
    u32::from(u16::from_le_bytes([image[at], image[at + 1]]))
}

fn u32_at(image: &Image, at: usize) -> u32 {
    u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]])
}

fn signed(image: &Image, at: usize) -> i32 {
    i32::from(image[at] as i8)
}

/// `ar9003_hw_atten_chain_get` / `_get_margin`: 2 GHz modal value, or the
/// 5 GHz three-point interpolation when the low extension is non-zero.
fn atten(image: &Image, frequency: u16, chain: usize, margin: bool) -> u32 {
    let (modal_field, low, high) = if margin {
        (
            modal::XATTEN1_MARGIN,
            field::EXT2_XATTEN1_MARGIN_LOW,
            field::EXT2_XATTEN1_MARGIN_HIGH,
        )
    } else {
        (
            modal::XATTEN1_DB,
            field::EXT2_XATTEN1_DB_LOW,
            field::EXT2_XATTEN1_DB_HIGH,
        )
    };
    if frequency < 4000 {
        return u32::from(image[field::MODAL_2G + modal_field + chain]);
    }
    let low = image[field::EXT2 + low + chain];
    let mid = image[field::MODAL_5G + modal_field + chain];
    if low == 0 {
        return u32::from(mid);
    }
    let value = power_interpolate(
        i32::from(frequency),
        &[5180, 5500, 5785],
        &[
            i32::from(low),
            i32::from(mid),
            i32::from(image[field::EXT2 + high + chain]),
        ],
    );
    u32::from(value as u16)
}

/// `ath9k_hw_ar9300_set_board_values` for `frequency` with the
/// `ah->rxchainmask`/`txchainmask` (= caps) masks and AR9300
/// `chip_chainmask` 7.
pub(in crate::ath9k) fn set_board_values(
    io: &mut impl RegisterIo,
    image: &Image,
    frequency: u16,
    rx_chainmask: u8,
    tx_chainmask: u8,
) -> Result<(), BringUpError> {
    let two = frequency < 4000;
    let m = modal_base(!two);
    let feature = image[field::FEATURE_ENABLE];
    let misc = image[field::MISC_CONFIGURATION];
    // ar9003_hw_xpa_timing_control_apply.
    if feature & 0x80 != 0 {
        let on = u32::from(image[m + modal::TX_FRAME_TO_XPA_ON]);
        if two {
            set_field(io, AR_PHY_XPA_TIMING_CTL, 0xff00, 8, on)?;
        } else {
            set_field(io, AR_PHY_XPA_TIMING_CTL, 0xff, 0, on)?;
        }
    }
    // ar9003_hw_xpa_bias_level_apply (AR9300 final branch).
    let bias = u32::from(image[m + modal::XPA_BIAS_LVL]);
    set_field(io, AR_CH0_TOP, 0x300, 8, bias)?;
    set_field(io, AR_CH0_THERM, 0x3, 0, bias >> 2)?;
    set_field(io, AR_CH0_THERM, 0x4, 2, 1)?;
    // ar9003_hw_ant_ctrl_apply.
    set_field(
        io,
        AR_PHY_SWITCH_COM,
        0xffff,
        0,
        u32_at(image, m + modal::ANT_CTRL_COMMON),
    )?;
    set_field(
        io,
        AR_PHY_SWITCH_COM_2,
        0x00ff_ffff,
        0,
        u32_at(image, m + modal::ANT_CTRL_COMMON2),
    )?;
    for (chain, register) in SWITCH_CHAIN.into_iter().enumerate() {
        if (rx_chainmask | tx_chainmask) & (1 << chain) != 0 {
            let value = u16_at(image, m + modal::ANT_CTRL_CHAIN + 2 * chain);
            set_field(io, register, 0xfff, 0, value)?;
        }
    }
    // ar9003_hw_drive_strength_apply.
    if misc & 1 != 0 {
        let fives = |shifts: &[u32]| shifts.iter().fold(0u32, |a, s| a | (5 << s));
        rmw(
            io,
            AR_PHY_65NM_CH0_BIAS1,
            0x00ff_ffc0,
            fives(&[21, 18, 15, 12, 9, 6]),
        )?;
        rmw(
            io,
            AR_PHY_65NM_CH0_BIAS2,
            0xffff_ffe0,
            fives(&[29, 26, 23, 20, 17, 14, 11, 8, 5]),
        )?;
        rmw(io, AR_PHY_65NM_CH0_BIAS4, 0xff80_0000, fives(&[29, 26, 23]))?;
    }
    // ar9003_hw_xlna_bias_strength_apply.
    if misc & 0x40 != 0 {
        let strength = u32::from(image[m + modal::XLNA_BIAS_STRENGTH]);
        for (chain, register) in RXTX4.into_iter().enumerate() {
            set_field(io, register, 0xc000_0000, 30, (strength >> (2 * chain)) & 3)?;
        }
    }
    // ar9003_hw_atten_apply (alt_mingainidx unset).
    for (chain, register) in EXT_ATTEN_CTL.into_iter().enumerate() {
        if tx_chainmask & (1 << chain) != 0 {
            set_field(io, register, 0x3f, 0, atten(image, frequency, chain, false))?;
            set_field(
                io,
                register,
                0x1f000,
                12,
                atten(image, frequency, chain, true),
            )?;
        }
    }
    // ar9003_hw_quick_drop_apply.
    if misc & 0x10 != 0 {
        let drop = if frequency < 4000 {
            signed(image, field::MODAL_2G + modal::QUICK_DROP)
        } else {
            power_interpolate(
                i32::from(frequency),
                &[5180, 5500, 5785],
                &[
                    signed(image, field::EXT1 + field::EXT1_QUICK_DROP_LOW),
                    signed(image, field::MODAL_5G + modal::QUICK_DROP),
                    signed(image, field::EXT1 + field::EXT1_QUICK_DROP_HIGH),
                ],
            )
        };
        set_field(io, AR_PHY_AGC, 0x03c0_0000, 22, drop as u32)?;
    }
    // ar9003_hw_internal_regulator_apply (AR9300 final branches).
    if feature & 0x10 != 0 {
        rmw(io, AR_RTC_REG_CONTROL1, 1, 0)?;
        io.write32(AR_RTC_REG_CONTROL0, u32_at(image, field::SWREG));
        rmw(io, AR_RTC_REG_CONTROL1, 0, 1)?;
    } else {
        rmw(io, AR_RTC_SLEEP_CLK, 0, 4)?; // AR_RTC_FORCE_SWREG_PRD.
    }
    // ar9003_hw_apply_tuning_caps.
    if feature & 0x40 != 0 {
        let caps = u32::from(image[field::TUNING_CAPS] & 0x7f);
        set_field(io, AR_CH0_XTAL, 0x7f00_0000, 24, caps)?;
        set_field(io, AR_CH0_XTAL, 0x00fe_0000, 17, caps)?;
    }
    // ar9003_hw_apply_minccapwr_thresh.
    let misc_enable = image[field::EXT1 + field::EXT1_MISC_ENABLE];
    if misc_enable & if two { 4 } else { 8 } != 0 {
        for (chain, register) in CCA_CTRL.into_iter().enumerate() {
            if tx_chainmask & (1 << chain) != 0 {
                let value = signed(image, m + modal::NOISE_FLOOR_THRESH + chain);
                set_field(io, register, 0x1ff, 0, value as u32)?;
            }
        }
    }
    // ar9003_hw_txend_to_xpa_off_apply.
    let off = u32::from(image[m + modal::TX_END_TO_XPA_OFF]);
    set_field(io, AR_PHY_XPA_TIMING_CTL, 0xff00_0000, 24, off)?;
    set_field(io, AR_PHY_XPA_TIMING_CTL, 0x00ff_0000, 16, off)?;
    // ar9003_hw_thermometer_apply (chip_chainmask 7).
    let thermometer = i32::from((misc >> 1) & 3) - 1;
    let on = u32::from(thermometer >= 0);
    for register in RXTX4 {
        set_field(io, register, 0x2000_0000, 29, on)?;
    }
    for (chain, register) in RXTX4.into_iter().enumerate() {
        set_field(
            io,
            register,
            0x1000_0000,
            28,
            u32::from(thermometer == chain as i32),
        )?;
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
