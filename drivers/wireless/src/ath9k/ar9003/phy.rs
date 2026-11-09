// SPDX-License-Identifier: GPL-2.0-or-later
//! `ar9003_phy.c` full-reset channel preparation for a 20 MHz AR9300
//! channel, in `hw.c::ath9k_hw_reset` order after the chip reset:
//! `ath9k_hw_init_pll` (`ar9003_hw_compute_pll_control`),
//! `ar9003_hw_process_ini` (SoC/MAC/BB/radio pre/core/post, the
//! `ar9003_doubler_fix`, RX/TX gain, the 5 GHz fast clock and the Japan
//! 2484 CCK FIR; `ar9003_hw_override_ini`, `ar9003_hw_set_channel_regs`,
//! `ar9003_hw_set_chain_masks`, `ath9k_hw_apply_txpower`),
//! `ar9003_hw_set_rfmode`, `ar9003_hw_set_delta_slope`,
//! `ar9003_hw_spur_mitigate` (MRC CCK + OFDM), `set_board_values` and
//! `ar9003_hw_set_channel`. PHY, interrupts and the receive engine stay
//! off; HT40, half/quarter rate and PAPRD are not prepared.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{
    board, eeprom::Identity, field, ini::Tables, power, power::Image, rmw, serdes::PllPwrsave,
    Revision,
};
use crate::ath9k::identity::{BringUpError, RegisterIo};

const AR_CR: u64 = 0x0008;
const AR_CR_RXD: u32 = 0x20;
const AR_IER: u64 = 0x0024;
const AR_Q_TXD: u64 = 0x0880;
const AR_GTXTO: u64 = 0x0064;
const AR_CST: u64 = 0x006c;
const AR_RTC_PLL_CONTROL: u64 = 0x7014;
const AR_RTC_SLEEP_CLK: u64 = 0x7048;
const AR_DIAG_SW: u64 = 0x8048;
const AR_DIAG_RX_DIS_ABORT: u32 = 0x0200_0020;
const AR_2040_MODE: u64 = 0x8318;
const AR_SELFGEN_MASK: u64 = 0x832c;
const AR_PCU_MISC_MODE2: u64 = 0x8344;
const AR_PHY_TIMING3: u64 = 0x9808;
const AR_PHY_TIMING4: u64 = 0x980c;
const AR_PHY_TIMING11: u64 = 0x9818;
const AR_PHY_SPUR_REG: u64 = 0x981c;
const AR_PHY_SFCORR_EXT: u64 = 0x982c;
const AR_PHY_PILOT_SPUR_MASK: u64 = 0x9c0c;
const AR_PHY_CHAN_SPUR_MASK: u64 = 0x9c10;
const AR_PHY_SGI_DELTA: u64 = 0x9c14;
const AR_PHY_CCK_SPUR_MIT: u64 = 0x9fcc;
const AR_PHY_GEN_CTRL: u64 = 0xa204;
const AR_PHY_MODE: u64 = 0xa208;
const AR_PHY_ACTIVE: u64 = 0xa20c;
const AR_PHY_SPUR_MASK_A: u64 = 0xa220;
const AR_PHY_RX_CHAINMASK: u64 = 0xa2a0;
const AR_PHY_CAL_CHAINMASK: u64 = 0xa2c0;
const AR_PHY_AGC_CONTROL: u64 = 0xa2c4;
const AR_PHY_CL_CAL_CTL: u64 = 0xa2d8;
const AR_PHY_SYNTH_CONTROL: u64 = 0xa340;
const AR_PHY_ANALOG_SWAP: u64 = 0xa34c;
const AR_PHY_65NM_CH0_SYNTH4: u64 = 0x1608c;
const AR_PHY_65NM_CH0_SYNTH7: u64 = 0x16098;
const AR_PHY_65NM_CH0_SYNTH12: u64 = 0x160ac;
const RXTX2: [u64; 3] = [0x16104, 0x16504, 0x16904];
const SYNTHON: u32 = 0x4;
const SYNTHOVR: u32 = 0x8;
/// `ar9003_hw_spur_mitigate_mrc_cck`'s fixed AR9300 CCK spur list.
const CCK_SPURS: [i32; 4] = [2420, 2440, 2464, 2480];

/// The facts a prepared channel retains for calibration and the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Prepared {
    pub frequency: u16,
    /// `ah->modes_index`.
    pub modes_index: usize,
    /// `ar9003_hw_override_ini`: `AR_PHY_CL_CAL_ENABLE` → `TX_CL_CAL`.
    pub carrier_leak_cal: bool,
    /// `ATH9K_HW_CAP_APM` (`EEP_CHAIN_MASK_REDUCE`) reduced selfgen mask.
    pub selfgen_mask: u8,
    pub power: power::Plan,
    /// Writes of the shared `regWrites` arrays (RX/TX gain, fast clock).
    pub ini_writes: u16,
}

/// `ath9k_hw_get_delta_slope_vals` (`COEF_SCALE_S` 24).
pub(in crate::ath9k) fn slope(coefficient: u32) -> (u32, u32) {
    let highest = 31 - coefficient.leading_zeros();
    let exponent = 38 - highest;
    let mantissa = coefficient + (1 << (24 - exponent - 1));
    (mantissa >> (24 - exponent), exponent - 16)
}

/// `ar9003_hw_set_channel`'s `channelSel` for an AR9300 (40 MHz
/// reference, fractional mode, 5 GHz doubler on).
pub(in crate::ath9k) fn channel_select(frequency: u16) -> (u32, bool) {
    let f = u32::from(frequency);
    if f < 4800 {
        (f * 0x10000 / 15, true)
    } else {
        ((f * 0x8000 / 15) >> 1, false)
    }
}

/// `ar9003_hw_prog_ini`: non-modal arrays force column 1; a local
/// `regWrites` count per array.
fn prog_ini<const C: usize>(io: &mut impl RegisterIo, rows: &[[u32; C]], column: usize) {
    let column = if column >= C { 1 } else { column };
    for (i, row) in rows.iter().enumerate() {
        io.write32(u64::from(row[0]), row[column]);
        if (i + 1) % 64 == 0 {
            io.delay_us(1);
        }
    }
}

/// `REG_WRITE_ARRAY` with the caller's shared `regWrites`.
fn write_array<const C: usize>(
    io: &mut impl RegisterIo,
    rows: &[[u32; C]],
    column: usize,
    count: &mut u16,
) {
    for row in rows {
        io.write32(u64::from(row[0]), row[column]);
        *count = count.wrapping_add(1);
        if *count % 64 == 0 {
            io.delay_us(1);
        }
    }
}

/// `ar9003_doubler_fix` (AR9300 branch).
fn doubler_fix(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    for register in RXTX2 {
        rmw(io, register, SYNTHON | SYNTHOVR, 0)?;
    }
    io.delay_us(200);
    for register in RXTX2 {
        rmw(io, register, SYNTHON, 0)?;
    }
    io.delay_us(1);
    for register in RXTX2 {
        field(io, register, SYNTHON, 2, 1)?;
    }
    io.delay_us(200);
    field(io, AR_PHY_65NM_CH0_SYNTH12, 0x0078_0000, 19, 0xf)?;
    for register in RXTX2 {
        rmw(io, register, 0, SYNTHON | SYNTHOVR)?;
    }
    Ok(())
}

/// `ar9003_hw_spur_mitigate_mrc_cck` for an AR9300 (fixed list, range 10).
fn spur_mrc_cck(io: &mut impl RegisterIo, frequency: u16) -> Result<(), BringUpError> {
    for spur in CCK_SPURS {
        let offset = spur - i32::from(frequency);
        if offset.abs() < 10 {
            let mut cck = (offset.abs() << 19) / 11;
            if offset < 0 {
                cck = -cck;
            }
            field(io, AR_PHY_AGC_CONTROL, 0x3c0, 6, 7)?;
            field(io, AR_PHY_CCK_SPUR_MIT, 0x1fe, 1, 0x7f)?;
            field(io, AR_PHY_CCK_SPUR_MIT, 0x6000_0000, 29, 2)?;
            field(io, AR_PHY_CCK_SPUR_MIT, 1, 0, 1)?;
            field(
                io,
                AR_PHY_CCK_SPUR_MIT,
                0x1fff_fe00,
                9,
                (cck & 0xfffff) as u32,
            )?;
            return Ok(());
        }
    }
    field(io, AR_PHY_AGC_CONTROL, 0x3c0, 6, 5)?;
    field(io, AR_PHY_CCK_SPUR_MIT, 1, 0, 0)?;
    field(io, AR_PHY_CCK_SPUR_MIT, 0x1fff_fe00, 9, 0)
}

/// The OFDM spur fields `ar9003_hw_spur_ofdm_clear` zeroes and
/// `ar9003_hw_spur_ofdm` sets, in Linux order.
const OFDM_SPUR_FIELDS: [(u64, u32, u32); 17] = [
    (AR_PHY_TIMING4, 0x4000_0000, 30),    // ENABLE_SPUR_FILTER
    (AR_PHY_TIMING11, 0x3ff0_0000, 20),   // SPUR_FREQ_SD
    (AR_PHY_TIMING11, 0x000f_ffff, 0),    // SPUR_DELTA_PHASE
    (AR_PHY_SFCORR_EXT, 0x1000_0000, 28), // SPUR_SUBCHANNEL_SD
    (AR_PHY_TIMING11, 0x4000_0000, 30),   // USE_SPUR_FILTER_IN_AGC
    (AR_PHY_TIMING11, 0x8000_0000, 31),   // USE_SPUR_FILTER_IN_SELFCOR
    (AR_PHY_TIMING4, 0x8000_0000, 31),    // ENABLE_SPUR_RSSI
    (AR_PHY_SPUR_REG, 0x100, 8),          // EN_VIT_SPUR_RSSI
    (AR_PHY_SPUR_REG, 0x0400_0000, 26),   // ENABLE_NF_RSSI_SPUR_MIT
    (AR_PHY_SPUR_REG, 0x0002_0000, 17),   // ENABLE_MASK_PPM
    (AR_PHY_TIMING4, 0x1000_0000, 28),    // ENABLE_PILOT_MASK
    (AR_PHY_TIMING4, 0x2000_0000, 29),    // ENABLE_CHAN_MASK
    (AR_PHY_PILOT_SPUR_MASK, 0xfe0, 5),   // CF_PILOT_MASK_IDX_A
    (AR_PHY_SPUR_MASK_A, 0x1fc00, 10),    // CF_PUNC_MASK_IDX_A
    (AR_PHY_CHAN_SPUR_MASK, 0xfe0, 5),    // CF_CHAN_MASK_IDX_A
    (AR_PHY_PILOT_SPUR_MASK, 0x1f, 0),    // CF_PILOT_MASK_A
    (AR_PHY_CHAN_SPUR_MASK, 0x1f, 0),     // CF_CHAN_MASK_A
];

/// `ar9003_hw_spur_mitigate_ofdm` for a 20 MHz channel over the band's
/// EEPROM `spurChans` (range 10, `synth_freq` the channel).
fn spur_ofdm(io: &mut impl RegisterIo, image: &Image, frequency: u16) -> Result<(), BringUpError> {
    let two = frequency < 4000;
    let spurs = super::eeprom::modal_base(!two) + super::eeprom::modal::SPUR_CHANS;
    if image[spurs] == 0 {
        return Ok(());
    }
    for &(register, mask, shift) in &OFDM_SPUR_FIELDS {
        field(io, register, mask, shift, 0)?;
    }
    field(io, AR_PHY_SPUR_MASK_A, 0x3ff, 0, 0)?; // CF_PUNC_MASK_A
    field(io, AR_PHY_SPUR_REG, 0x03fc_0000, 18, 0)?; // MASK_RATE_CNTL
    for i in 0..5 {
        let bin = image[spurs + i];
        if bin == 0 {
            break;
        }
        let offset = super::eeprom::fbin2freq(bin, two) - i32::from(frequency);
        if offset.abs() >= 10 {
            continue;
        }
        // ar9003_hw_spur_ofdm_work (HT20) then ar9003_hw_spur_ofdm.
        let freq_sd = ((offset << 9) / 11) & 0x3ff;
        let delta_phase = ((offset << 18) / 5) & 0xfffff;
        field(io, AR_PHY_TIMING4, 0x4000_0000, 30, 1)?;
        field(io, AR_PHY_TIMING11, 0x3ff0_0000, 20, freq_sd as u32)?;
        field(io, AR_PHY_TIMING11, 0x000f_ffff, 0, delta_phase as u32)?;
        field(io, AR_PHY_SFCORR_EXT, 0x1000_0000, 28, 0)?;
        field(io, AR_PHY_TIMING11, 0x4000_0000, 30, 1)?;
        field(io, AR_PHY_TIMING11, 0x8000_0000, 31, 1)?;
        field(io, AR_PHY_TIMING4, 0x8000_0000, 31, 1)?;
        field(io, AR_PHY_SPUR_REG, 0xff, 0, 34)?;
        field(io, AR_PHY_SPUR_REG, 0x100, 8, 1)?;
        let mode = io.read32(AR_PHY_MODE);
        if mode == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        if (mode & 0x4) >> 2 == 1 {
            field(io, AR_PHY_SPUR_REG, 0x0400_0000, 26, 1)?;
        }
        let mut mask_index = (offset << 4) / 5;
        if mask_index < 0 {
            mask_index -= 1;
        }
        let mask_index = (mask_index & 0x7f) as u32;
        field(io, AR_PHY_SPUR_REG, 0x0002_0000, 17, 1)?;
        field(io, AR_PHY_TIMING4, 0x1000_0000, 28, 1)?;
        field(io, AR_PHY_TIMING4, 0x2000_0000, 29, 1)?;
        field(io, AR_PHY_PILOT_SPUR_MASK, 0xfe0, 5, mask_index)?;
        field(io, AR_PHY_SPUR_MASK_A, 0x1fc00, 10, mask_index)?;
        field(io, AR_PHY_CHAN_SPUR_MASK, 0xfe0, 5, mask_index)?;
        field(io, AR_PHY_PILOT_SPUR_MASK, 0x1f, 0, 0xc)?;
        field(io, AR_PHY_CHAN_SPUR_MASK, 0x1f, 0, 0xc)?;
        field(io, AR_PHY_SPUR_MASK_A, 0x3ff, 0, 0xa0)?;
        field(io, AR_PHY_SPUR_REG, 0x03fc_0000, 18, 0xff)?;
        break;
    }
    Ok(())
}

/// Whether `frequency` is a 20 MHz center this preparation covers in a
/// band the EEPROM enables (`AR5416_OPFLAGS_11G` / `_11A`).
pub(in crate::ath9k) fn channel_supported(identity: &Identity, frequency: u16) -> bool {
    match frequency {
        2412..=2472 => frequency % 5 == 2 && identity.op_flags & 0x2 != 0,
        2484 => identity.op_flags & 0x2 != 0,
        5180..=5825 => frequency % 5 == 0 && identity.op_flags & 0x1 != 0,
        _ => false,
    }
}

/// The last `AR_PHY_CL_CAL_CTL` value `rows` writes in `column`
/// (`prog_ini`'s column rule).
fn last_cl<const C: usize>(rows: &[[u32; C]], column: usize, seen: &mut Option<u32>) {
    let column = if column >= C { 1 } else { column };
    for row in rows {
        if u64::from(row[0]) == AR_PHY_CL_CAL_CTL {
            *seen = Some(row[column]);
        }
    }
}

/// The facts [`prepare`] returns at `frequency`, derived without touching
/// the chip: the same channel and power-plan checks, the modes index, the
/// APM selfgen mask, the shared `regWrites` count of the RX/TX gain and
/// fast-clock arrays, and `TX_CL_CAL` from the last INI row (in
/// `ar9003_hw_process_ini` order) that writes `AR_PHY_CL_CAL_CTL`. No later
/// step of `prepare` before its readback writes that register; without
/// such a row the readback is a hardware default and the facts are
/// refused.
pub(in crate::ath9k) fn expected(
    revision: &Revision,
    identity: &Identity,
    pll_pwrsave: PllPwrsave,
    image: &Image,
    frequency: u16,
    ctl: u16,
    power_limit: u8,
) -> Result<Prepared, BringUpError> {
    if !channel_supported(identity, frequency) {
        return Err(BringUpError::Policy);
    }
    let plan = power::plan(image, frequency, ctl, power_limit, identity.tx_chainmask)?;
    let tables = Tables::for_revision(revision, identity, pll_pwrsave);
    let five = frequency >= 4800;
    let modes_index = if five { 1 } else { 4 };
    let mut cl = None;
    last_cl(tables.soc_pre, modes_index, &mut cl);
    // The BB pre array is AR9485-only; empty for the other chips.
    last_cl(tables.bb_pre, modes_index, &mut cl);
    last_cl(tables.mac_core, modes_index, &mut cl);
    last_cl(tables.bb_core, modes_index, &mut cl);
    last_cl(tables.radio_core, modes_index, &mut cl);
    last_cl(tables.soc_post, modes_index, &mut cl);
    last_cl(tables.mac_post, modes_index, &mut cl);
    last_cl(tables.bb_post, modes_index, &mut cl);
    last_cl(tables.radio_post, modes_index, &mut cl);
    // The allmodes radio postamble is AR9485-only; empty otherwise.
    last_cl(tables.radio_post_allmodes, modes_index, &mut cl);
    last_cl(tables.rx_gain, 1, &mut cl);
    last_cl(tables.tx_gain, modes_index, &mut cl);
    let mut writes = (tables.rx_gain.len() as u16).wrapping_add(tables.tx_gain.len() as u16);
    // RX-gain overrides are written with the gain arrays (see `prepare`);
    // the sys2ant postamble is a `prog_ini` array and carries no
    // `AR_PHY_CL_CAL_CTL` row, so it changes neither count nor leak bit.
    writes = writes
        .wrapping_add(tables.rxgain_bb_core.len() as u16)
        .wrapping_add(tables.rxgain_bb_postamble.len() as u16)
        .wrapping_add(tables.rxgain_xlna.len() as u16);
    if five {
        last_cl(tables.fast_clock, modes_index, &mut cl);
        writes = writes.wrapping_add(tables.fast_clock.len() as u16);
    }
    if frequency == 2484 {
        last_cl(tables.cck_fir_japan_2484, 1, &mut cl);
    }
    let cl = cl.ok_or(BringUpError::BadState)?;
    let apm = image[super::eeprom::field::MISC_CONFIGURATION] & 0x8 != 0;
    let tx = identity.tx_chainmask;
    Ok(Prepared {
        frequency,
        modes_index,
        carrier_leak_cal: cl & 0x2 != 0,
        selfgen_mask: if apm && tx == 7 { 3 } else { tx },
        power: plan,
        ini_writes: writes,
    })
}

/// Inactive full-reset preparation of one 20 MHz AR9300 channel after a
/// chip reset (`ar9003::set_reset` + `set_power_awake`). `ctl` and
/// `power_limit` are `ath9k_hw_apply_txpower`'s inputs. The power plan is
/// computed before the first write.
#[allow(
    clippy::too_many_arguments,
    reason = "keep per-device identity and reset policy explicit alongside channel power inputs"
)]
pub(in crate::ath9k) fn prepare(
    io: &mut impl RegisterIo,
    revision: &Revision,
    identity: &Identity,
    pll_pwrsave: PllPwrsave,
    image: &Image,
    frequency: u16,
    ctl: u16,
    power_limit: u8,
) -> Result<Prepared, BringUpError> {
    if !channel_supported(identity, frequency) {
        return Err(BringUpError::Policy);
    }
    let plan = power::plan(image, frequency, ctl, power_limit, identity.tx_chainmask)?;
    let tables = Tables::for_revision(revision, identity, pll_pwrsave);
    let five = frequency >= 4800;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_IER, 0);
    io.write32(AR_Q_TXD, 0x3ff);
    io.write32(AR_CR, AR_CR_RXD);
    rmw(io, AR_DIAG_SW, 0, AR_DIAG_RX_DIS_ABORT)?;
    io.write32(AR_PHY_ACTIVE, 0); // ar9003_hw_mark_phy_inactive.
                                  // ath9k_hw_init_pll: REFDIV 5, DIV 0x2c, RTC_PLL_SETTLE_DELAY 100.
    io.write32(AR_RTC_PLL_CONTROL, (5 << 10) | 0x2c);
    io.delay_us(100);
    io.write32(AR_RTC_SLEEP_CLK, 2); // AR_RTC_FORCE_DERIVED_CLK.

    // ar9003_hw_process_ini.
    let modes_index = if five { 1 } else { 4 };
    prog_ini(io, tables.soc_pre, modes_index);
    // The BB pre array is AR9485-only; empty for the other chips.
    prog_ini(io, tables.bb_pre, modes_index);
    prog_ini(io, tables.mac_core, modes_index);
    prog_ini(io, tables.bb_core, modes_index);
    prog_ini(io, tables.radio_core, modes_index);
    prog_ini(io, tables.soc_post, modes_index);
    prog_ini(io, tables.mac_post, modes_index);
    prog_ini(io, tables.bb_post, modes_index);
    prog_ini(io, tables.radio_post, modes_index);
    // `ar9003_phy.c` programs `ini_radio_post_sys2ant` here for
    // `AR_SREV_9462_20_OR_LATER`; empty for the AR9300/AR9580.
    prog_ini(io, tables.radio_post_sys2ant, modes_index);
    // The allmodes radio postamble is AR9485-only; empty otherwise.
    prog_ini(io, tables.radio_post_allmodes, modes_index);
    doubler_fix(io)?;
    let mut writes = 0;
    write_array(io, tables.rx_gain, 1, &mut writes);
    // `ar9003_phy.c` RXGAIN overrides: the mix baseband core (column 1)
    // and postamble (modes column) for RX mode 2, and the XLNA array
    // (modes column) for RX modes 2/3; empty for every other mode.
    write_array(io, tables.rxgain_bb_core, 1, &mut writes);
    write_array(io, tables.rxgain_bb_postamble, modes_index, &mut writes);
    write_array(io, tables.rxgain_xlna, modes_index, &mut writes);
    write_array(io, tables.tx_gain, modes_index, &mut writes);
    if five {
        // IS_CHAN_A_FAST_CLOCK: ATH9K_HW_CAP_FASTCLOCK on every AR9300.
        write_array(io, tables.fast_clock, modes_index, &mut writes);
    }
    if frequency == 2484 {
        prog_ini(io, tables.cck_fir_japan_2484, 1);
    }
    // ar9003_hw_override_ini.
    rmw(io, AR_DIAG_SW, 0, AR_DIAG_RX_DIS_ABORT)?;
    let misc = io.read32(AR_PCU_MISC_MODE2);
    if misc == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    // ~ADHOC_MCAST_KEYID | AGG_WEP_FIX | AGG_WEP | CFP_IGNORE.
    io.write32(AR_PCU_MISC_MODE2, (misc & !0x40) | 0x8 | 0x2_0000 | 0x80);
    let cl = io.read32(AR_PHY_CL_CAL_CTL);
    if cl == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    // ar9003_hw_set_channel_regs (HT20): HT_EN | SHORT_GI_40 | DAC FIFO |
    // SINGLE_HT_LTF1, INI bits kept, GF detect off.
    let gen = io.read32(AR_PHY_GEN_CTRL);
    if gen == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    let phymode = 0x40 | 0x80 | (gen & 0x800) | 0x200;
    let gen = io.read32(AR_PHY_GEN_CTRL);
    if gen == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_PHY_GEN_CTRL, (phymode | gen) & !0x400);
    io.write32(AR_2040_MODE, 0);
    io.write32(AR_GTXTO, 25 << 16);
    io.write32(AR_CST, 0xf << 16);
    // ar9003_hw_set_chain_masks.
    let (rx, tx) = (identity.rx_chainmask, identity.tx_chainmask);
    if rx == 5 || tx == 5 {
        rmw(io, AR_PHY_ANALOG_SWAP, 0, 0x40)?;
    }
    io.write32(AR_PHY_RX_CHAINMASK, u32::from(rx));
    io.write32(AR_PHY_CAL_CHAINMASK, u32::from(rx));
    let apm = image[super::eeprom::field::MISC_CONFIGURATION] & 0x8 != 0;
    let selfgen_mask = if apm && tx == 7 { 3 } else { tx };
    io.write32(AR_SELFGEN_MASK, u32::from(selfgen_mask));
    power::program(io, &plan)?;

    // ar9003_hw_set_rfmode: 2 GHz DYNAMIC; 5 GHz OFDM + fast clock
    // DYNAMIC | DYN_CCK_DISABLE.
    io.write32(AR_PHY_MODE, if five { 0x104 } else { 0x4 });
    // ar9003_hw_set_delta_slope (full rate, synth center).
    let coefficient = 0x6400_0000 / u32::from(frequency);
    let (mantissa, exponent) = slope(coefficient);
    field(io, AR_PHY_TIMING3, 0xfffe_0000, 17, mantissa)?;
    field(io, AR_PHY_TIMING3, 0x1e000, 13, exponent)?;
    let (mantissa, exponent) = slope(9 * coefficient / 10);
    field(io, AR_PHY_SGI_DELTA, 0x7fff0, 4, mantissa)?;
    field(io, AR_PHY_SGI_DELTA, 0xf, 0, exponent)?;
    spur_mrc_cck(io, frequency)?;
    spur_ofdm(io, image, frequency)?;
    board::set_board_values(io, image, frequency, rx, tx)?;
    // ar9003_hw_set_channel.
    let (select, two) = channel_select(frequency);
    io.write32(AR_PHY_SYNTH_CONTROL, u32::from(two) << 29);
    field(io, AR_PHY_65NM_CH0_SYNTH4, 0x2, 1, 1)?;
    let synth = (select << 2) | (1 << 30);
    io.write32(AR_PHY_65NM_CH0_SYNTH7, synth);
    io.write32(AR_PHY_65NM_CH0_SYNTH7, synth | (1 << 31));
    io.write32(AR_PHY_ACTIVE, 0);
    io.write32(AR_IER, 0);
    io.write32(AR_CR, AR_CR_RXD);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(Prepared {
        frequency,
        modes_index,
        carrier_leak_cal: cl & 0x2 != 0,
        selfgen_mask,
        power: plan,
        ini_writes: writes,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
