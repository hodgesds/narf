// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C radio calibration inputs from one completed native factory owner.
//!
//! Mirrors Linux 7.3-rc4 rtw8852c.c `rtw8852c_efuse_parsing_tssi`,
//! `rtw8852c_efuse_parsing_gain_offset` (logical map, `struct rtw8852c_efuse`)
//! and `rtw8852c_read_phycap` (`phycap_addr` 0x590, `phycap_size` 0x60).
//! Only actual factory bytes are decoded; nothing is defaulted except Linux's
//! explicit erased-TSSI-trim interpretation after a complete read.
use super::{
    factory::{Factory, C_PHYCAP_ADDR},
    mac::ChipId,
};

/// `RTW89_GAIN_OFFSET_*` order: 2G CCK, 2G OFDM, 5G low/mid/high, then
/// 6G L0, L1, M0, M1, H0, H1, UH0, UH1.
pub(super) const GAIN_OFFSET_NR: usize = 13;
/// Logical-map byte for each `RTW89_GAIN_OFFSET_*` (rtw8852c.h packed layout).
pub(super) const GAIN_OFFSET_ADDR: [usize; GAIN_OFFSET_NR] = [
    0x2d6, 0x2d4, 0x2d8, 0x2da, 0x2dc, 0x3a8, 0x3aa, 0x3ac, 0x3ae, 0x3b0, 0x3b2, 0x3b4, 0x3b6,
];
/// `rtw8852c_efuse.path_{a,b}_tssi` (`struct rtw8852c_tssi_offset`).
const TSSI_BASE: [usize; 2] = [0x210, 0x23a];
/// `rtw8852c_efuse.bw40_1s_tssi_6g_{a,b}`.
const TSSI_6G_BASE: [usize; 2] = [0x300, 0x32a];
/// rtw8852c.c `tssi_trim_addr`, `tssi_trim_addr_6g`, `thm_trim_addr`,
/// `pabias_trim_addr` (physical addresses; trim entries decrease).
const TSSI_TRIM: [usize; 2] = [0x5d6, 0x5ab];
const TSSI_TRIM_6G: [usize; 2] = [0x5ce, 0x5a3];
const THERMAL_TRIM: [usize; 2] = [0x5df, 0x5dc];
const PA_BIAS_TRIM: [usize; 2] = [0x5de, 0x5db];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Calibration {
    pub thermal: [u8; 2],
    /// `TSSI_CCK_CH_GROUP_NUM` = 6.
    pub tssi_cck: [[i8; 6]; 2],
    /// `TSSI_MCS_2G_CH_GROUP_NUM` 5 + `TSSI_MCS_5G_CH_GROUP_NUM` 14.
    pub tssi_mcs: [[i8; 19]; 2],
    /// `TSSI_MCS_6G_CH_GROUP_NUM` = 32.
    pub tssi_6g_mcs: [[i8; 32]; 2],
    /// `TSSI_TRIM_CH_GROUP_NUM` = 8.
    pub tssi_trim: [[i8; 8]; 2],
    /// `TSSI_TRIM_CH_GROUP_NUM_6G` = 16.
    pub tssi_trim_6g: [[i8; 16]; 2],
    pub trim_programmed: bool,
    pub thermal_trim: [u8; 2],
    pub thermal_programmed: bool,
    pub pa_bias: [u8; 2],
    pub pa_programmed: bool,
    pub gain_offset: [[i8; GAIN_OFFSET_NR]; 2],
    pub offset_valid: bool,
}
impl Calibration {
    pub fn from_factory(factory: &Factory) -> Option<Self> {
        if factory.identity()?.chip() != ChipId::Rtl8852C {
            return None;
        }
        let logical = factory.logical()?;
        let physical = factory.c_phycap()?;
        let phy = |address: usize| physical[address - usize::from(C_PHYCAP_ADDR)];
        let mut result = Self {
            thermal: [*logical.get(0x2d0)?, *logical.get(0x2d1)?],
            tssi_cck: [[0; 6]; 2],
            tssi_mcs: [[0; 19]; 2],
            tssi_6g_mcs: [[0; 32]; 2],
            tssi_trim: [[0; 8]; 2],
            tssi_trim_6g: [[0; 16]; 2],
            trim_programmed: false,
            thermal_trim: [phy(THERMAL_TRIM[0]), phy(THERMAL_TRIM[1])],
            thermal_programmed: false,
            pa_bias: [phy(PA_BIAS_TRIM[0]), phy(PA_BIAS_TRIM[1])],
            pa_programmed: false,
            gain_offset: [[0; GAIN_OFFSET_NR]; 2],
            offset_valid: false,
        };
        for path in 0..2 {
            let base = TSSI_BASE[path];
            // cck_tssi[6], bw40_tssi[5], rsvd[7], bw40_1s_tssi_5g[14].
            for i in 0..6 {
                result.tssi_cck[path][i] = *logical.get(base + i)? as i8;
            }
            for i in 0..5 {
                result.tssi_mcs[path][i] = *logical.get(base + 6 + i)? as i8;
            }
            for i in 0..14 {
                result.tssi_mcs[path][5 + i] = *logical.get(base + 0x12 + i)? as i8;
            }
            for i in 0..32 {
                result.tssi_6g_mcs[path][i] = *logical.get(TSSI_6G_BASE[path] + i)? as i8;
            }
            for i in 0..8 {
                let value = phy(TSSI_TRIM[path] - i);
                result.tssi_trim[path][i] = value as i8;
                result.trim_programmed |= value != 255;
            }
            for i in 0..16 {
                let value = phy(TSSI_TRIM_6G[path] - i);
                result.tssi_trim_6g[path][i] = value as i8;
                result.trim_programmed |= value != 255;
            }
        }
        // `rtw8852c_phycap_parsing_tssi`: no programmed trim at all clears
        // both trim arrays, after the complete PHY-cap read only.
        if !result.trim_programmed {
            result.tssi_trim = [[0; 8]; 2];
            result.tssi_trim_6g = [[0; 16]; 2];
        }
        result.thermal_programmed = result.thermal_trim.iter().any(|&v| v != 255);
        result.pa_programmed = result.pa_bias.iter().any(|&v| v != 255);
        // `_decode_efuse_gain`: high nibble path A, low nibble path B (signed).
        for (band, address) in GAIN_OFFSET_ADDR.into_iter().enumerate() {
            let value = *logical.get(address)?;
            result.gain_offset[0][band] = (value as i8) >> 4;
            result.gain_offset[1][band] = ((value << 4) as i8) >> 4;
            result.offset_valid |= value != 255;
        }
        Some(result)
    }
    /// rtw8852c.c `rtw8852c_thermal_trim` `__thm_setting`: RR_TM2 OFF value.
    pub fn thermal_setting(&self, path: usize) -> Option<u8> {
        let raw = *self.thermal_trim.get(path)?;
        self.thermal_programmed
            .then_some(((raw & 1) << 3) | ((raw & 0x0e) >> 1))
    }
    /// rtw8852c.c `rtw8852c_pa_bias_trim`: (RR_BIASA_TXG, RR_BIASA_TXA).
    pub fn pa_bias_setting(&self, path: usize) -> Option<(u8, u8)> {
        let raw = *self.pa_bias.get(path)?;
        self.pa_programmed.then_some((raw & 0x0f, raw >> 4))
    }
}
