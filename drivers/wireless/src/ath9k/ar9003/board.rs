// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_eeprom.c::ath9k_hw_ar9300_set_board_values` per chip: xPA
//! timing, xPA bias, antenna switch tables, drive strength, xLNA bias,
//! xatten, quick drop, the RTC/PMU internal regulator, crystal tuning
//! caps, minCCApwr thresholds, TX-end-to-xPA-off, the thermometer
//! selection and (AR9462-only) `thermo_cal`.
//!
//! Every helper follows its Linux branch table on `Chip`: the AR9300
//! branch is the baseline the earlier lane ported, and the AR9580 shares
//! it (`AR_SREV_9300` is true for both); the AR9462/AR9565 take the
//! `AR_CH0_TOP` / `AR_SWITCH_TABLE_COM_AR9462` / SPDT / PMU1 arms, and
//! the AR9485 the `AR_CH0_TOP2` / antenna-diversity / PMU1+PMU2 arms.
//! Branches that need a board value no in-tree source supplies —
//! `bt_ant_diversity` and the `ath_hw_config` fields (`xlna_gpio`,
//! `ant_ctrl_comm2g_switch_enable`, `xatten_margin_cfg`,
//! `alt_mingainidx`) — are NOT implemented here: the unconditional base
//! write is ported, the board-conditional delta is left for the
//! board-config follow-up (see the PR body). No 5 GHz per-chip refusal
//! is added: that is the open §5 design question (#1382), not a lane
//! decision.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    eeprom::{self, field, modal, modal_base},
    field as set_field,
    power::{power_interpolate, Image},
    rmw, Chip,
};
use crate::ath9k::identity::{BringUpError, RegisterIo};

const AR_PHY_XPA_TIMING_CTL: u64 = 0xa264;
const AR_CH0_TOP: u64 = 0x16288;
/// `ar9003_phy.h::AR_CH0_TOP(ah)` for AR9462/AR9565.
const AR_CH0_TOP_9462_9565: u64 = 0x1628c;
/// `ar9003_phy.h::AR_CH0_TOP2(ah)` for the AR9485 (neither AR9300 nor
/// AR9462).
const AR_CH0_TOP2_9485: u64 = 0x16284;
const AR_CH0_THERM: u64 = 0x16290;
const AR_CH0_XTAL: u64 = 0x16294;
/// `ar9003_phy.h::AR_CH0_XTAL(ah)` for AR9462/AR9565.
const AR_CH0_XTAL_9462_9565: u64 = 0x16298;
/// `ar9003_phy.h::AR_CH0_XTAL(ah)` for the AR9485.
const AR_CH0_XTAL_9485: u64 = 0x16290;
const AR_PHY_SWITCH_COM: u64 = 0xa288;
const AR_PHY_SWITCH_COM_2: u64 = 0xa28c;
/// `ar9003_phy.h::AR_PHY_GLB_CONTROL` (`AR_GLB_BASE + 0x44`).
const AR_PHY_GLB_CONTROL: u64 = 0x20044;
/// `ar9003_phy.h::AR_PHY_MC_GAIN_CTRL` (`AR_AGC_BASE + 0x28`).
const AR_PHY_MC_GAIN_CTRL: u64 = 0x9e28;
/// `ar9003_phy.h::AR_PHY_CCK_DETECT` (`AR_AGC_BASE + 0x1c0`).
const AR_PHY_CCK_DETECT: u64 = 0x9fc0;
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
/// `ar9003_phy.h::AR_PHY_PMU1(ah)` for AR9462/AR9565.
const AR_PHY_PMU1_9462_9565: u64 = 0x16340;
/// `ar9003_phy.h::AR_PHY_PMU1(ah)` for the AR9485.
const AR_PHY_PMU1_9485: u64 = 0x16c40;
/// `ar9003_phy.h::AR_PHY_PMU2(ah)` for the AR9485.
const AR_PHY_PMU2_9485: u64 = 0x16c44;
/// `ar9003_phy.h::AR_PHY_BB_THERM_ADC_3` (`AR_SM_BASE + 0x250`).
const AR_PHY_BB_THERM_ADC_3: u64 = 0xa450;
/// `ar9003_eeprom.h::AR9300_EEP_ANTDIV_CONTROL_DEFAULT_VALUE`.
const ANT_DIV_CONTROL_DEFAULT: u32 = 0xc9;

fn u16_at(image: &Image, at: usize) -> u32 {
    u32::from(u16::from_le_bytes([image[at], image[at + 1]]))
}

fn u32_at(image: &Image, at: usize) -> u32 {
    u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]])
}

fn signed(image: &Image, at: usize) -> i32 {
    i32::from(image[at] as i8)
}

/// `ar9003_phy.h::AR_CH0_XTAL(ah)`.
fn xtal(chip: Chip) -> u64 {
    match chip {
        Chip::Ar9300 | Chip::Ar9580 => AR_CH0_XTAL,
        Chip::Ar9462 | Chip::Ar9565 => AR_CH0_XTAL_9462_9565,
        Chip::Ar9485 => AR_CH0_XTAL_9485,
    }
}

/// `ar9003_hw_xpa_timing_control_apply`: `featureEnable & 0x80`, and
/// only the AR9300/AR9580 (Linux's `AR_SREV_9300` arm) apply it — the
/// AR9462/AR9485/AR9565 return without a write.
fn xpa_timing_control_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    m: usize,
    two: bool,
    chip: Chip,
) -> Result<(), BringUpError> {
    if image[field::FEATURE_ENABLE] & 0x80 == 0 {
        return Ok(());
    }
    if !matches!(chip, Chip::Ar9300 | Chip::Ar9580) {
        return Ok(());
    }
    let on = u32::from(image[m + modal::TX_FRAME_TO_XPA_ON]);
    if two {
        set_field(io, AR_PHY_XPA_TIMING_CTL, 0xff00, 8, on)
    } else {
        set_field(io, AR_PHY_XPA_TIMING_CTL, 0xff, 0, on)
    }
}

/// `ar9003_hw_xpa_bias_level_apply`: the AR9485 writes `AR_CH0_TOP2`
/// (`AR_CH0_TOP2_XPABIASLVL` 0xf000, shift 12); the AR9462/AR9565 write
/// `AR_CH0_TOP` (`AR_CH0_TOP_XPABIASLVL` 0x300, shift 8); the
/// AR9300/AR9580 write `AR_CH0_TOP` plus the `AR_CH0_THERM` MSB and
/// `XPASHORT2GND`.
fn xpa_bias_level_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    m: usize,
    chip: Chip,
) -> Result<(), BringUpError> {
    let bias = u32::from(image[m + modal::XPA_BIAS_LVL]);
    match chip {
        Chip::Ar9485 => set_field(io, AR_CH0_TOP2_9485, 0xf000, 12, bias),
        Chip::Ar9462 | Chip::Ar9565 => set_field(io, AR_CH0_TOP_9462_9565, 0x300, 8, bias),
        Chip::Ar9300 | Chip::Ar9580 => {
            set_field(io, AR_CH0_TOP, 0x300, 8, bias)?;
            set_field(io, AR_CH0_THERM, 0x3, 0, bias >> 2)?;
            set_field(io, AR_CH0_THERM, 0x4, 2, 1)
        }
    }
}

/// `ar9003_hw_ant_ctrl_apply`. The AR9485 xLNA-GPIO branch
/// (`rx_gain_idx == 0`, `ah->config.xlna_gpio`) and the AR9485
/// `bt_ant_diversity` mask of `antCtrlCommon2` need board config with no
/// in-tree source and are left for the board-config follow-up; the
/// unconditional switch-table writes below are Linux's for every chip.
fn ant_ctrl_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    m: usize,
    chip: Chip,
    rx_chainmask: u8,
    tx_chainmask: u8,
) -> Result<(), BringUpError> {
    let value = u32_at(image, m + modal::ANT_CTRL_COMMON);
    // `AR_SWITCH_TABLE_COM_AR9462_ALL` 0xffffff for the AR9462/AR9565,
    // `AR_SWITCH_TABLE_COM_ALL` 0xffff for the rest.
    let mask = if matches!(chip, Chip::Ar9462 | Chip::Ar9565) {
        0xffff_ff
    } else {
        0xffff
    };
    set_field(io, AR_PHY_SWITCH_COM, mask, 0, value)?;
    // `AR_SREV_9462_20_OR_LATER || AR_SREV_9565`: the SPDT switch table
    // and the `AR_BTCOEX_CTRL_SPDT_ENABLE` bit of `AR_PHY_GLB_CONTROL`
    // (in-tree AR9462 silicon is 2.0/2.1 only, so 20-or-later holds).
    if matches!(chip, Chip::Ar9462 | Chip::Ar9565) {
        let spdt = u16_at(image, m + modal::SWITCH_COM_SPDT);
        set_field(io, AR_PHY_GLB_CONTROL, 0xfff0, 4, spdt)?;
        rmw(io, AR_PHY_GLB_CONTROL, 0, 0x1)?;
    }
    let value = u32_at(image, m + modal::ANT_CTRL_COMMON2);
    set_field(io, AR_PHY_SWITCH_COM_2, 0x00ff_ffff, 0, value)?;
    // `AR_SREV_9462 && rxchainmask == 0x2`: chain 1's table into
    // `AR_PHY_SWITCH_CHAIN_0`.
    if chip == Chip::Ar9462 && rx_chainmask == 0x2 {
        let value = u16_at(image, m + modal::ANT_CTRL_CHAIN + 2);
        set_field(io, SWITCH_CHAIN[0], 0xfff, 0, value)?;
    }
    for (chain, register) in SWITCH_CHAIN.into_iter().enumerate() {
        if (rx_chainmask | tx_chainmask) & (1 << chain) != 0 {
            let value = u16_at(image, m + modal::ANT_CTRL_CHAIN + 2 * chain);
            set_field(io, register, 0xfff, 0, value)?;
        }
    }
    // Antenna diversity (`AR_SREV_9330 || AR_SREV_9485 || AR_SREV_9565`):
    // `EEP_ANT_DIV_CTL1` is the EEPROM `ant_div_control` byte, except the
    // AR9565, which uses `AR9300_EEP_ANTDIV_CONTROL_DEFAULT_VALUE`. The
    // `bt_ant_diversity` adjustments (AR9485 `AR_ANT_DIV_ENABLE`, the
    // AR9565 RX-protect / force-on arms) need board config and are left
    // for the board-config follow-up.
    if matches!(chip, Chip::Ar9485 | Chip::Ar9565) {
        let value = if chip == Chip::Ar9565 {
            ANT_DIV_CONTROL_DEFAULT
        } else {
            u32::from(image[field::EXT1 + field::EXT1_ANT_DIV_CONTROL])
        };
        rmw(io, AR_PHY_MC_GAIN_CTRL, 0x7e00_0000, (value & 0x3f) << 25)?;
        rmw(
            io,
            AR_PHY_MC_GAIN_CTRL,
            0x0100_0000,
            ((value >> 6) & 0x1) << 24,
        )?;
        rmw(io, AR_PHY_CCK_DETECT, 0x2000, ((value >> 7) & 0x1) << 13)?;
        // `hw.c::ath9k_hw_fill_cap_info`: LNA combining when
        // `(ant_div_ctl1 >> 6) == 0x3` — main LNA1, alt LNA2
        // (`phy.h::ATH_ANT_DIV_COMB_LNA1` 2, `_LNA2` 1).
        if (value >> 6) == 0x3 {
            rmw(io, AR_PHY_MC_GAIN_CTRL, 0x7e00_0000, (2 << 27) | (1 << 25))?;
        }
    }
    Ok(())
}

/// `ar9003_hw_drive_strength_apply` (chip-independent).
fn drive_strength_apply(io: &mut impl RegisterIo, image: &Image) -> Result<(), BringUpError> {
    if image[field::MISC_CONFIGURATION] & 1 == 0 {
        return Ok(());
    }
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
    rmw(io, AR_PHY_65NM_CH0_BIAS4, 0xff80_0000, fives(&[29, 26, 23]))
}

/// `ar9003_hw_xlna_bias_strength_apply`: `miscConfiguration & 0x40`,
/// and only `AR_SREV_9300` (AR9300/AR9580) applies it.
fn xlna_bias_strength_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    m: usize,
    chip: Chip,
) -> Result<(), BringUpError> {
    if image[field::MISC_CONFIGURATION] & 0x40 == 0 {
        return Ok(());
    }
    if !matches!(chip, Chip::Ar9300 | Chip::Ar9580) {
        return Ok(());
    }
    let strength = u32::from(image[m + modal::XLNA_BIAS_STRENGTH]);
    for (chain, register) in RXTX4.into_iter().enumerate() {
        set_field(io, register, 0xc000_0000, 30, (strength >> (2 * chain)) & 3)?;
    }
    Ok(())
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

/// `ar9003_hw_atten_apply` (the `alt_mingainidx` write and the AR9485
/// `rx_gain_idx == 0 && xatten_margin_cfg` margin-5 override need board
/// config / the gain index and are left for the board-config follow-up).
fn atten_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    frequency: u16,
    chip: Chip,
    rx_chainmask: u8,
    tx_chainmask: u8,
) -> Result<(), BringUpError> {
    // `AR_SREV_9462 && rxchainmask == 0x2`: chain 1's attenuation into
    // `AR_PHY_EXT_ATTEN_CTL_0`.
    if chip == Chip::Ar9462 && rx_chainmask == 0x2 {
        set_field(
            io,
            EXT_ATTEN_CTL[0],
            0x3f,
            0,
            atten(image, frequency, 1, false),
        )?;
        set_field(
            io,
            EXT_ATTEN_CTL[0],
            0x1f000,
            12,
            atten(image, frequency, 1, true),
        )?;
    }
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
    Ok(())
}

/// `ar9003_hw_quick_drop_apply`: only `AR_SREV_9300 || AR_SREV_9580`
/// (Linux's arm; the AR9462/AR9485/AR9565 return without a write).
fn quick_drop_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    frequency: u16,
    chip: Chip,
) -> Result<(), BringUpError> {
    if image[field::MISC_CONFIGURATION] & 0x10 == 0 {
        return Ok(());
    }
    if !matches!(chip, Chip::Ar9300 | Chip::Ar9580) {
        return Ok(());
    }
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
    set_field(io, AR_PHY_AGC, 0x03c0_0000, 22, drop as u32)
}

/// `ar9003_eeprom.c::is_pmu_set`: the register already holds `value`, or
/// takes it within 100 rewrites 10 µs apart. Read-first, like Linux: a
/// register that already holds the value is never rewritten.
fn pmu_set(io: &mut impl RegisterIo, register: u64, value: u32) -> bool {
    let mut timeout = 100;
    while io.read32(register) != value {
        if timeout == 0 {
            return false;
        }
        timeout -= 1;
        io.write32(register, value);
        io.delay_us(10);
    }
    true
}

/// `ar9003_hw_internal_regulator_apply`.
fn internal_regulator_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    chip: Chip,
) -> Result<(), BringUpError> {
    let feature = image[field::FEATURE_ENABLE];
    if feature & 0x10 != 0 {
        match chip {
            Chip::Ar9485 => {
                // `AR_SREV_9485`: the fixed PMU set. A step that never
                // sticks aborts the rest of the regulator sequence, as
                // Linux's early `return` does.
                let mut pmu = io.read32(AR_PHY_PMU2_9485) & !0x0020_0000;
                io.write32(AR_PHY_PMU2_9485, pmu);
                if !pmu_set(io, AR_PHY_PMU2_9485, pmu) {
                    return Ok(());
                }
                pmu = 0x131c_827a;
                io.write32(AR_PHY_PMU1_9485, pmu);
                if !pmu_set(io, AR_PHY_PMU1_9485, pmu) {
                    return Ok(());
                }
                pmu = (io.read32(AR_PHY_PMU2_9485) & !0xffc0_0000) | (4 << 26);
                io.write32(AR_PHY_PMU2_9485, pmu);
                if !pmu_set(io, AR_PHY_PMU2_9485, pmu) {
                    return Ok(());
                }
                pmu = (io.read32(AR_PHY_PMU2_9485) & !0x0020_0000) | (1 << 21);
                io.write32(AR_PHY_PMU2_9485, pmu);
                if !pmu_set(io, AR_PHY_PMU2_9485, pmu) {
                    return Ok(());
                }
            }
            Chip::Ar9462 | Chip::Ar9565 => {
                io.write32(AR_PHY_PMU1_9462_9565, u32_at(image, field::SWREG));
            }
            Chip::Ar9300 | Chip::Ar9580 => {
                rmw(io, AR_RTC_REG_CONTROL1, 1, 0)?;
                io.write32(AR_RTC_REG_CONTROL0, u32_at(image, field::SWREG));
                rmw(io, AR_RTC_REG_CONTROL1, 0, 1)?;
            }
        }
    } else {
        match chip {
            Chip::Ar9485 => {
                // Linux spins these polls unboundedly; NARF bounds them
                // at the driver's usual 100 ms wait and fails closed.
                set_field(io, AR_PHY_PMU2_9485, 0x0020_0000, 21, 0)?;
                io.wait_us(AR_PHY_PMU2_9485, 0x0020_0000, 0, 100_000)?;
                set_field(io, AR_PHY_PMU1_9485, 0x1, 0, 1)?;
                io.wait_us(AR_PHY_PMU1_9485, 0x1, 0x1, 100_000)?;
                set_field(io, AR_PHY_PMU2_9485, 0x0020_0000, 21, 1)?;
                io.wait_us(AR_PHY_PMU2_9485, 0x0020_0000, 0x0020_0000, 100_000)?;
            }
            Chip::Ar9462 | Chip::Ar9565 => {
                set_field(io, AR_PHY_PMU1_9462_9565, 0x1, 0, 1)?;
            }
            Chip::Ar9300 | Chip::Ar9580 => {
                rmw(io, AR_RTC_SLEEP_CLK, 0, 4)?; // AR_RTC_FORCE_SWREG_PRD.
            }
        }
    }
    Ok(())
}

/// `ar9003_hw_apply_tuning_caps` with the per-chip `AR_CH0_XTAL`.
fn apply_tuning_caps(
    io: &mut impl RegisterIo,
    image: &Image,
    chip: Chip,
) -> Result<(), BringUpError> {
    if image[field::FEATURE_ENABLE] & 0x40 == 0 {
        return Ok(());
    }
    let caps = u32::from(image[field::TUNING_CAPS] & 0x7f);
    let xtal = xtal(chip);
    set_field(io, xtal, 0x7f00_0000, 24, caps)?;
    set_field(io, xtal, 0x00fe_0000, 17, caps)
}

/// `ar9003_hw_apply_minccapwr_thresh`.
fn apply_minccapwr_thresh(
    io: &mut impl RegisterIo,
    image: &Image,
    two: bool,
    tx_chainmask: u8,
) -> Result<(), BringUpError> {
    let misc_enable = image[field::EXT1 + field::EXT1_MISC_ENABLE];
    if misc_enable & if two { 4 } else { 8 } != 0 {
        let m = modal_base(!two);
        for (chain, register) in CCA_CTRL.into_iter().enumerate() {
            if tx_chainmask & (1 << chain) != 0 {
                let value = signed(image, m + modal::NOISE_FLOOR_THRESH + chain);
                set_field(io, register, 0x1ff, 0, value as u32)?;
            }
        }
    }
    Ok(())
}

/// `ar9003_hw_txend_to_xpa_off_apply`.
fn txend_to_xpa_off_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    m: usize,
) -> Result<(), BringUpError> {
    let off = u32::from(image[m + modal::TX_END_TO_XPA_OFF]);
    set_field(io, AR_PHY_XPA_TIMING_CTL, 0xff00_0000, 24, off)?;
    set_field(io, AR_PHY_XPA_TIMING_CTL, 0x00ff_0000, 16, off)
}

/// `ar9003_hw_thermometer_apply`: the override and per-chain select only
/// on chains the chip has (`chip_chainmask`).
fn thermometer_apply(
    io: &mut impl RegisterIo,
    image: &Image,
    chip: Chip,
) -> Result<(), BringUpError> {
    let thermometer = i32::from((image[field::MISC_CONFIGURATION] >> 1) & 3) - 1;
    let on = u32::from(thermometer >= 0);
    let mask = chip.chip_chainmask();
    for (chain, register) in RXTX4.into_iter().enumerate() {
        if mask & (1 << chain) != 0 {
            set_field(io, register, 0x2000_0000, 29, on)?;
        }
    }
    for (chain, register) in RXTX4.into_iter().enumerate() {
        if mask & (1 << chain) != 0 {
            set_field(
                io,
                register,
                0x1000_0000,
                28,
                u32::from(thermometer == chain as i32),
            )?;
        }
    }
    Ok(())
}

/// `ar9003_hw_thermo_cal_apply` (AR9462 2.0+ only): OTP word 1's `ko`/`kg`
/// into `AR_PHY_BB_THERM_ADC_3`. Linux ignores a failed OTP read (`data`
/// stays 0), so the wait failure is the no-write case here, not an
/// error; a failed register write still fails the bring-up.
fn thermo_cal_apply(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    let _ = io.read32(eeprom::AR9300_OTP_BASE + 4);
    let data = match io.wait_us(
        eeprom::AR9300_OTP_STATUS,
        eeprom::AR9300_OTP_STATUS_TYPE,
        eeprom::AR9300_OTP_STATUS_VALID,
        1000,
    ) {
        Ok(_) => io.read32(eeprom::AR9300_OTP_READ_DATA),
        Err(_) => 0,
    };
    let ko = data & 0xff;
    let kg = (data >> 8) & 0xff;
    if ko != 0 || kg != 0 {
        set_field(io, AR_PHY_BB_THERM_ADC_3, 0xff, 0, ko)?;
        set_field(io, AR_PHY_BB_THERM_ADC_3, 0x1ff00, 8, kg + 256)?;
    }
    Ok(())
}

/// `ath9k_hw_ar9300_set_board_values` for `frequency` on `chip`, with the
/// `ah->rxchainmask`/`txchainmask` (= caps) masks. `set_board_values` is
/// skipped for the AR9330/AR9340/AR9531 in Linux; every in-tree chip
/// calls the regulator step.
pub(in crate::ath9k) fn set_board_values(
    io: &mut impl RegisterIo,
    chip: Chip,
    image: &Image,
    frequency: u16,
    rx_chainmask: u8,
    tx_chainmask: u8,
) -> Result<(), BringUpError> {
    let two = frequency < 4000;
    let m = modal_base(!two);
    xpa_timing_control_apply(io, image, m, two, chip)?;
    xpa_bias_level_apply(io, image, m, chip)?;
    ant_ctrl_apply(io, image, m, chip, rx_chainmask, tx_chainmask)?;
    drive_strength_apply(io, image)?;
    xlna_bias_strength_apply(io, image, m, chip)?;
    atten_apply(io, image, frequency, chip, rx_chainmask, tx_chainmask)?;
    quick_drop_apply(io, image, frequency, chip)?;
    internal_regulator_apply(io, image, chip)?;
    apply_tuning_caps(io, image, chip)?;
    apply_minccapwr_thresh(io, image, two, tx_chainmask)?;
    txend_to_xpa_off_apply(io, image, m)?;
    thermometer_apply(io, image, chip)?;
    if chip == Chip::Ar9462 {
        thermo_cal_apply(io)?;
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
