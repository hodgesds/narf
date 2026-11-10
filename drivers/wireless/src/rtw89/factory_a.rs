// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A radio calibration inputs from one completed native factory owner.
//!
//! Mirrors Linux rtw8852a.h `struct rtw8852a_efuse` (`path_a_tssi` 0x210,
//! `path_b_tssi` 0x23a, `path_a_therm` 0x2d0, `path_b_therm` 0x2d1) and
//! rtw8852a.c `rtw8852a_efuse_parsing_tssi`,
//! `rtw8852a_phycap_parsing_{tssi,thermal_trim,pa_bias_trim}`
//! (`tssi_trim_addr` {0x5d6, 0x5ab}, `thm_trim_addr` {0x5df, 0x5dc},
//! `pabias_trim_addr` {0x5de, 0x5db}; `phycap_addr` 0x580, `phycap_size`
//! 128). Only actual factory bytes are decoded; nothing is defaulted
//! except Linux's explicit erased-TSSI-trim interpretation after a
//! complete read. Linux parses no gain offset/compensation for A (those
//! bytes are reserved in `struct rtw8852a_efuse`), so this calibration
//! carries none, unlike the B one.
use super::{
    factory::{Factory, A_PHYCAP_ADDR},
    mac::ChipId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Calibration {
    pub thermal: [u8; 2],
    pub tssi_cck: [[i8; 6]; 2],
    pub tssi_mcs: [[i8; 19]; 2],
    pub tssi_trim: [[i8; 8]; 2],
    pub trim_programmed: bool,
    pub thermal_trim: [u8; 2],
    pub thermal_programmed: bool,
    pub pa_bias: [u8; 2],
    pub pa_programmed: bool,
}
impl Calibration {
    pub fn from_factory(factory: &Factory) -> Option<Self> {
        if factory.identity()?.chip() != ChipId::Rtl8852A {
            return None;
        }
        let logical = factory.logical()?;
        let physical = factory.a_phycap()?;
        let phy = usize::from(A_PHYCAP_ADDR);
        let mut result = Self {
            thermal: [logical[0x2d0], logical[0x2d1]],
            tssi_cck: [[0; 6]; 2],
            tssi_mcs: [[0; 19]; 2],
            tssi_trim: [[0; 8]; 2],
            trim_programmed: false,
            thermal_trim: [physical[0x5df - phy], physical[0x5dc - phy]],
            thermal_programmed: false,
            pa_bias: [physical[0x5de - phy], physical[0x5db - phy]],
            pa_programmed: false,
        };
        for (path, base) in [0x210, 0x23a].into_iter().enumerate() {
            for i in 0..6 {
                result.tssi_cck[path][i] = logical[base + i] as i8;
            }
            for i in 0..5 {
                result.tssi_mcs[path][i] = logical[base + 6 + i] as i8;
            }
            for i in 0..14 {
                result.tssi_mcs[path][5 + i] = logical[base + 0x12 + i] as i8;
            }
        }
        for (path, address) in [0x5d6, 0x5ab].into_iter().enumerate() {
            for i in 0..8 {
                let value = physical[address - phy - i];
                result.tssi_trim[path][i] = value as i8;
                result.trim_programmed |= value != 255;
            }
        }
        // Linux's explicit erased-map interpretation applies only after all
        //128 actual bytes were read successfully. Partial I/O never gets here.
        if !result.trim_programmed {
            result.tssi_trim = [[0; 8]; 2];
        }
        result.thermal_programmed = result.thermal_trim.iter().any(|&v| v != 255);
        result.pa_programmed = result.pa_bias.iter().any(|&v| v != 255);
        Some(result)
    }
}
