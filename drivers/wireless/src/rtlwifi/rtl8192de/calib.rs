// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE IQK calibration reload (`rtl92d_phy_reload_iqk_setting`,
//! `rtl8192de/phy.c:2362`).
//!
//! The reload runs at the end of the channel switch
//! (`_rtl92d_phy_sw_chnl_step_by_step`, after the `RF_CHNLBW` command
//! and the RF-setting switch: "do IQK when all parameters are ready").
//! Linux's re-calibration branch is dead code (`0 &&
//! !iqk_matrix[index].iqk_done && need_iqk`), so the reload always
//! takes the load path: for the channel's IQK place
//! ([`super::channel::iqk_place`]) it fills the stored path-A matrix
//! when `value[0][0] != 0`, and on a single-PHY chip the path-B
//! matrix when `value[0][4] != 0`; a 2.4 GHz place loads only until
//! the IMR reload has run once (`load_imrandiqk_setting_for2g`),
//! while 5 GHz places always load. `need_iqk` clears either way.
//!
//! Only the reload instantiation is ported: the fill helpers run
//! with `iqk_ok = true` and the single stored candidate, exactly as
//! the reload calls them. The live calibration
//! (`rtl92d_phy_iq_calibrate`, `rtl92d_linked_set_reg`) and the LCK
//! calibration (`rtl92d_phy_lc_calibrate`, with the
//! `targetchnl_2g` / `targetchnl_5g` curve tables and the LCK
//! reload) are later lanes. Arithmetic follows Linux bit for bit:
//! the 10-bit sign extension and the `u32` wrapping multiply with a
//! logical shift for the TX words, the `long` (signed) arithmetic
//! for the TX-C words, and the unmasked `set_bb` write
//! ([`super::phy::set_bb`], as in `rtl92d_phy_set_bb_reg`).

use super::channel::iqk_place;
use super::phy;
use super::{Band, MacPhyMode};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `IQK_MATRIX_REG_NUM` (`wifi.h`): 8 result words per channel place.
pub const IQK_MATRIX_REG_NUM: usize = 8;
/// `IQK_MATRIX_SETTINGS_NUM` (`wifi.h`): 1 + 24 + 21 places — index 0
/// is 2.4 GHz, 1..=45 are the 5 GHz places from [`iqk_place`].
pub const IQK_MATRIX_SETTINGS_NUM: usize = 46;

/// One channel place's stored IQK result (`struct iqk_matrix_regs`,
/// `wifi.h`): `long value[1][IQK_MATRIX_REG_NUM]` plus `iqk_done`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IqkSetting {
    pub value: [i64; IQK_MATRIX_REG_NUM],
    pub iqk_done: bool,
}

impl IqkSetting {
    /// `rtl92d_phy_reset_iqk_result` values for one place: the even
    /// words `0x100`, the odd words `0`, not done.
    pub const fn reset() -> Self {
        Self {
            value: [0x100, 0, 0x100, 0, 0x100, 0, 0x100, 0],
            iqk_done: false,
        }
    }
}

/// The `rtlphy->iqk_matrix` plus the `need_iqk` and
/// `load_imrandiqk_setting_for2g` flags (`rtlhal` / `rtlphy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IqkMatrix {
    pub settings: [IqkSetting; IQK_MATRIX_SETTINGS_NUM],
    /// Set when an auth frame is transmitted (`rtl_tx_mgmt_proc`,
    /// `base.c`); cleared by every reload.
    pub need_iqk: bool,
    /// Set by the IMR reload after the first 2.4 GHz load
    /// (`_rtl92d_phy_reload_imr_setting`); the reload itself only
    /// reads it.
    pub load_imrandiqk_setting_for2g: bool,
}

impl IqkMatrix {
    /// The post-`rtl92d_phy_reset_iqk_result` state
    /// (`rtl8192de/phy.c:2684`): every place reset, no IQK pending,
    /// no 2.4 GHz IMR load yet. `rtl92de_hw_init` resets before any
    /// channel switch, so this is the state a fresh switch starts
    /// from.
    pub const fn new() -> Self {
        Self {
            settings: [IqkSetting::reset(); IQK_MATRIX_SETTINGS_NUM],
            need_iqk: false,
            load_imrandiqk_setting_for2g: false,
        }
    }

    /// `rtl92d_phy_reset_iqk_result`: every place back to the reset
    /// values, none done. The flags are untouched, as in Linux.
    pub fn reset(&mut self) {
        self.settings = [IqkSetting::reset(); IQK_MATRIX_SETTINGS_NUM];
    }
}

// NOTE: no `#[derive(Default)]` — `settings` is a 46-element array
// and `Default` is capped at 32 elements on the pinned toolchain,
// so the derive fails with E0277. The manual impl delegates to
// the existing `const fn new()`; do not re-add the derive.
impl Default for IqkMatrix {
    fn default() -> Self {
        Self::new()
    }
}

/// The HAL context the fill helpers read: single-PHY selection,
/// MAC/PHY mode, interface index and current band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IqkContext {
    /// `IS_92D_SINGLEPHY(version)`.
    pub single_phy: bool,
    pub mode: MacPhyMode,
    pub interface_index: u8,
    pub band: Band,
}

fn sign_extend_10(value: u32) -> u32 {
    if value & 0x0000_0200 != 0 {
        value | 0xffff_fc00
    } else {
        value
    }
}

fn sign_extend_10_long(value: i64) -> i64 {
    if value & 0x0000_0200 != 0 {
        value | 0xffff_fc00
    } else {
        value
    }
}

/// `_rtl92d_phy_patha_fill_iqk_matrix` (`rtl8192de/phy.c:2124`) for
/// the reload instantiation (`iqk_ok = true`, single stored
/// candidate). `txonly` (`value[0][2] == 0` at the call site) skips
/// the RX part. `is2t` is `IS_92D_SINGLEPHY(version) ||
/// macphymode == DUALMAC_DUALPHY`.
#[allow(clippy::too_many_arguments)]
fn fill_path_a(
    io: &impl Io,
    result: &[i64; IQK_MATRIX_REG_NUM],
    iqk_ok: bool,
    txonly: bool,
    is2t: bool,
    interface_index: u8,
    band: Band,
) -> Result<(), Error> {
    if !iqk_ok {
        return Ok(());
    }
    let oldval_0 = (phy::get_bb(io, phy::ROFDM0_XATXIQIMBALANCE, phy::MASKDWORD)? >> 22) & 0x3ff;
    let val_x = sign_extend_10(result[0] as u32);
    let tx0_a = val_x.wrapping_mul(oldval_0) >> 8;
    phy::set_bb(io, phy::ROFDM0_XATXIQIMBALANCE, 0x3ff, tx0_a)?;
    phy::set_bb(
        io,
        phy::ROFDM0_ECCATHRESHOLD,
        1 << 24,
        (val_x.wrapping_mul(oldval_0) >> 7) & 0x1,
    )?;
    let mut val_y = sign_extend_10_long(result[1]);
    // Path B IQK result + 3 (Linux comment, verbatim condition).
    if interface_index == 1 && band == Band::On5Ghz {
        val_y += 3;
    }
    let tx0_c = (val_y * i64::from(oldval_0)) >> 8;
    phy::set_bb(
        io,
        phy::ROFDM0_XCTXAFE,
        0xf000_0000,
        ((tx0_c & 0x3c0) >> 6) as u32,
    )?;
    phy::set_bb(
        io,
        phy::ROFDM0_XATXIQIMBALANCE,
        0x003f_0000,
        (tx0_c & 0x3f) as u32,
    )?;
    if is2t {
        phy::set_bb(
            io,
            phy::ROFDM0_ECCATHRESHOLD,
            1 << 26,
            (((val_y * i64::from(oldval_0)) >> 7) & 0x1) as u32,
        )?;
    }
    if txonly {
        return Ok(());
    }
    let reg = result[2] as u32;
    phy::set_bb(io, phy::ROFDM0_XARXIQIMBALANCE, 0x3ff, reg)?;
    let reg = (result[3] & 0x3f) as u32;
    phy::set_bb(io, phy::ROFDM0_XARXIQIMBALANCE, 0xfc00, reg)?;
    let reg = ((result[3] >> 6) & 0xf) as u32;
    phy::set_bb(io, 0xca0, 0xf000_0000, reg)?;
    Ok(())
}

/// `_rtl92d_phy_pathb_fill_iqk_matrix` (`rtl8192de/phy.c:2186`) for
/// the reload instantiation. `txonly` is `value[0][6] == 0` at the
/// call site.
fn fill_path_b(
    io: &impl Io,
    result: &[i64; IQK_MATRIX_REG_NUM],
    iqk_ok: bool,
    txonly: bool,
    band: Band,
) -> Result<(), Error> {
    if !iqk_ok {
        return Ok(());
    }
    let oldval_1 = (phy::get_bb(io, phy::ROFDM0_XBTXIQIMBALANCE, phy::MASKDWORD)? >> 22) & 0x3ff;
    let val_x = sign_extend_10(result[4] as u32);
    let tx1_a = val_x.wrapping_mul(oldval_1) >> 8;
    phy::set_bb(io, phy::ROFDM0_XBTXIQIMBALANCE, 0x3ff, tx1_a)?;
    phy::set_bb(
        io,
        phy::ROFDM0_ECCATHRESHOLD,
        1 << 28,
        (val_x.wrapping_mul(oldval_1) >> 7) & 0x1,
    )?;
    let mut val_y = sign_extend_10_long(result[5]);
    if band == Band::On5Ghz {
        val_y += 3;
    }
    let tx1_c = (val_y * i64::from(oldval_1)) >> 8;
    phy::set_bb(
        io,
        phy::ROFDM0_XDTXAFE,
        0xf000_0000,
        ((tx1_c & 0x3c0) >> 6) as u32,
    )?;
    phy::set_bb(
        io,
        phy::ROFDM0_XBTXIQIMBALANCE,
        0x003f_0000,
        (tx1_c & 0x3f) as u32,
    )?;
    phy::set_bb(
        io,
        phy::ROFDM0_ECCATHRESHOLD,
        1 << 30,
        (((val_y * i64::from(oldval_1)) >> 7) & 0x1) as u32,
    )?;
    if txonly {
        return Ok(());
    }
    let reg = result[6] as u32;
    phy::set_bb(io, phy::ROFDM0_XBRXIQIMBALANCE, 0x3ff, reg)?;
    let reg = (result[7] & 0x3f) as u32;
    phy::set_bb(io, phy::ROFDM0_XBRXIQIMBALANCE, 0xfc00, reg)?;
    let reg = ((result[7] >> 6) & 0xf) as u32;
    phy::set_bb(io, phy::ROFDM0_AGCRSSITABLE, 0x0000_f000, reg)?;
    Ok(())
}

/// `rtl92d_phy_reload_iqk_setting` (`rtl8192de/phy.c:2362`). Loads
/// the stored matrix for `channel`'s IQK place; a 2.4 GHz place
/// loads only until the IMR reload has run once, 5 GHz places
/// always load. `need_iqk` clears whether or not anything loaded.
pub fn reload_iqk_setting(
    io: &impl Io,
    channel: u8,
    matrix: &mut IqkMatrix,
    ctx: &IqkContext,
) -> Result<(), Error> {
    let index = iqk_place(channel);
    if (!matrix.load_imrandiqk_setting_for2g && index == 0) || index > 0 {
        let setting = matrix.settings[usize::from(index)];
        if setting.value[0] != 0 {
            fill_path_a(
                io,
                &setting.value,
                true,
                setting.value[2] == 0,
                ctx.single_phy || ctx.mode == MacPhyMode::DualMacDualPhy,
                ctx.interface_index,
                ctx.band,
            )?;
        }
        if ctx.single_phy && setting.value[4] != 0 {
            fill_path_b(io, &setting.value, true, setting.value[6] == 0, ctx.band)?;
        }
    }
    matrix.need_iqk = false;
    Ok(())
}
