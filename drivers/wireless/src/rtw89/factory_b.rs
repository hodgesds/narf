// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B radio calibration inputs from one completed native factory owner.
use super::{factory::Factory, mac::ChipId};

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
    pub gain_offset: [[i8; 5]; 2],
    pub offset_valid: bool,
    pub gain_comp: [[i8; 5]; 2],
    pub comp_valid: bool,
}
impl Calibration {
    pub fn from_factory(factory: &Factory) -> Option<Self> {
        if factory.identity()?.chip() != ChipId::Rtl8852B {
            return None;
        }
        let logical = factory.logical()?;
        let physical = factory.b_phycap()?;
        let mut result = Self {
            thermal: [logical[0x2d0], logical[0x2d1]],
            tssi_cck: [[0; 6]; 2],
            tssi_mcs: [[0; 19]; 2],
            tssi_trim: [[0; 8]; 2],
            trim_programmed: false,
            thermal_trim: [physical[0x5df - 0x580], physical[0x5dc - 0x580]],
            thermal_programmed: false,
            pa_bias: [physical[0x5de - 0x580], physical[0x5db - 0x580]],
            pa_programmed: false,
            gain_offset: [[0; 5]; 2],
            offset_valid: false,
            gain_comp: [[0; 5]; 2],
            comp_valid: false,
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
                let value = physical[address - 0x580 - i];
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
        for (band, address) in [0x2d6, 0x2d4, 0x2d8, 0x2da, 0x2dc].into_iter().enumerate() {
            let value = logical[address];
            result.gain_offset[0][band] = (value as i8) >> 4;
            result.gain_offset[1][band] = ((value << 4) as i8) >> 4;
            result.offset_valid |= value != 255;
        }
        for (path, addresses) in [
            [0x5bb, 0x5ba, 0, 0x5b9, 0x5b8],
            [0x590, 0x58f, 0, 0x58e, 0x58d],
        ]
        .into_iter()
        .enumerate()
        {
            for (band, address) in addresses.into_iter().enumerate() {
                if address == 0 {
                    continue;
                }
                let value = physical[address - 0x580];
                result.gain_comp[path][band] = ((value << 4) as i8) >> 4;
                result.comp_valid |= value != 255;
            }
        }
        Some(result)
    }
}
