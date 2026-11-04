// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B radio calibration inputs from one completed native factory owner.
//!
//! Mirrors Linux 7.3-rc4 rtw8851b.c `rtw8851b_efuse_parsing_tssi`,
//! `rtw8851b_efuse_parsing_gain_offset` (logical map, `struct rtw8851b_efuse`
//! in rtw8851b.h) and `rtw8851b_read_phycap` (`phycap_addr` 0x580,
//! `phycap_size` 128): TSSI trim, thermal trim, PA-bias trim, gain
//! compensation and the ADC TD selector. RTL8851B has one RF path
//! (`RF_PATH_NUM_8851B` = 1), so every value here is path A only. Only actual
//! factory bytes are decoded; nothing is defaulted except Linux's explicit
//! erased-TSSI-trim interpretation after a complete read.
use super::{factory::Factory, mac::ChipId};

const PHYCAP_ADDR: usize = 0x580;
/// `RTW89_GAIN_OFFSET_*` order 2G CCK, 2G OFDM, 5G low/mid/high: the
/// `rx_gain_*` bytes of `struct rtw8851b_efuse`.
pub(super) const GAIN_OFFSET_ADDR: [usize; 5] = [0x2d6, 0x2d4, 0x2d8, 0x2da, 0x2dc];
/// `struct rtw8851b_efuse.path_a_tssi` (`struct rtw8851b_tssi_offset`).
pub(super) const TSSI_BASE: usize = 0x210;
/// `struct rtw8851b_efuse.path_a_therm`.
pub(super) const THERMAL: usize = 0x2d0;
/// rtw8851b.c `tssi_trim_addr`, `thm_trim_addr`, `pabias_trim_addr`,
/// `rtw8851b_phycap_parsing_gain_comp` `comp_addrs[0]` and `addr_adc_td`
/// (physical addresses; TSSI trim entries decrease).
pub(super) const TSSI_TRIM: usize = 0x5d6;
pub(super) const THERMAL_TRIM: usize = 0x5df;
pub(super) const PA_BIAS_TRIM: usize = 0x5de;
pub(super) const GAIN_COMP: [usize; 5] = [0x5bb, 0x5ba, 0, 0x5b9, 0x5b8];
pub(super) const ADC_TD: usize = 0x5af;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Calibration {
    pub thermal: u8,
    /// `TSSI_CCK_CH_GROUP_NUM` = 6.
    pub tssi_cck: [i8; 6],
    /// `TSSI_MCS_2G_CH_GROUP_NUM` 5 + `TSSI_MCS_5G_CH_GROUP_NUM` 14.
    pub tssi_mcs: [i8; 19],
    /// `TSSI_TRIM_CH_GROUP_NUM` = 8.
    pub tssi_trim: [i8; 8],
    pub trim_programmed: bool,
    pub thermal_trim: u8,
    pub thermal_programmed: bool,
    pub pa_bias: u8,
    pub pa_programmed: bool,
    /// `efuse_gain.offset[RF_PATH_A]` (high nibble only, as Linux).
    pub gain_offset: [i8; 5],
    pub offset_valid: bool,
    /// `efuse_gain.comp[RF_PATH_A]` per `RTW89_SUBBAND_2GHZ_5GHZ_NR`; the
    /// unused 5GHz-band-1 slot stays zero.
    pub gain_comp: [i8; 5],
    pub comp_valid: bool,
    /// `efuse->adc_td` (bits [4:0] of physical 0x5af), read by
    /// `rtw8851b_bw_setting`.
    pub adc_td: u8,
}
impl Calibration {
    pub fn from_factory(factory: &Factory) -> Option<Self> {
        if factory.identity()?.chip() != ChipId::Rtl8851B {
            return None;
        }
        let logical = factory.logical()?;
        let physical = factory.n51_phycap()?;
        let phy = |address: usize| physical[address - PHYCAP_ADDR];
        let mut result = Self {
            thermal: *logical.get(THERMAL)?,
            tssi_cck: [0; 6],
            tssi_mcs: [0; 19],
            tssi_trim: [0; 8],
            trim_programmed: false,
            thermal_trim: phy(THERMAL_TRIM),
            thermal_programmed: false,
            pa_bias: phy(PA_BIAS_TRIM),
            pa_programmed: false,
            gain_offset: [0; 5],
            offset_valid: false,
            gain_comp: [0; 5],
            comp_valid: false,
            adc_td: phy(ADC_TD) & 0x1f,
        };
        // cck_tssi[6], bw40_tssi[5], rsvd[7], bw40_1s_tssi_5g[14].
        for i in 0..6 {
            result.tssi_cck[i] = *logical.get(TSSI_BASE + i)? as i8;
        }
        for i in 0..5 {
            result.tssi_mcs[i] = *logical.get(TSSI_BASE + 6 + i)? as i8;
        }
        for i in 0..14 {
            result.tssi_mcs[5 + i] = *logical.get(TSSI_BASE + 0x12 + i)? as i8;
        }
        for i in 0..8 {
            let value = phy(TSSI_TRIM - i);
            result.tssi_trim[i] = value as i8;
            result.trim_programmed |= value != 255;
        }
        // `rtw8851b_phycap_parsing_tssi`: no programmed trim clears the
        // array, after the complete PHY-cap read only.
        if !result.trim_programmed {
            result.tssi_trim = [0; 8];
        }
        result.thermal_programmed = result.thermal_trim != 255;
        result.pa_programmed = result.pa_bias != 255;
        // `_decode_efuse_gain(data, &offset[RF_PATH_A][band], NULL)`: only the
        // high nibble, sign-extended.
        for (band, address) in GAIN_OFFSET_ADDR.into_iter().enumerate() {
            let value = *logical.get(address)?;
            result.gain_offset[band] = (value as i8) >> 4;
            result.offset_valid |= value != 255;
        }
        // `_decode_efuse_gain(data, NULL, &comp[path][i])`: low nibble.
        for (band, address) in GAIN_COMP.into_iter().enumerate() {
            if address == 0 {
                continue;
            }
            let value = phy(address);
            result.gain_comp[band] = ((value << 4) as i8) >> 4;
            result.comp_valid |= value != 255;
        }
        Some(result)
    }
    /// rtw8851b.c `rtw8851b_thermal_trim` `__thm_setting` (RR_TM2 OFF),
    /// literally `((v & 0x1) << 3) | ((v & 0x1f) >> 1)` — note the 0x1f mask
    /// differs from RTL8852C's 0x0e.
    pub fn thermal_setting(&self) -> Option<u8> {
        let raw = self.thermal_trim;
        self.thermal_programmed
            .then_some(((raw & 1) << 3) | ((raw & 0x1f) >> 1))
    }
    /// rtw8851b.c `rtw8851b_pa_bias_trim`: (RR_BIASA_TXG, RR_BIASA_TXA).
    pub fn pa_bias_setting(&self) -> Option<(u8, u8)> {
        let raw = self.pa_bias;
        self.pa_programmed.then_some((raw & 0x0f, raw >> 4))
    }
}
