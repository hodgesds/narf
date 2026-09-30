//! Negotiated legacy rates and firmware TLC v6 rate adaptation.
use super::boot_context::{put16, put32};
use alloc::vec::Vec;
const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];

#[derive(Copy, Clone, Debug)]
pub struct Rates {
    pub supported: u16,
    pub basic: u16,
}
impl Rates {
    pub fn parse(ies: &[u8], channel: u8) -> Result<Self, &'static str> {
        Self::parse_for_phy(ies, channel, 0)
    }

    pub fn parse_for_phy(mut ies: &[u8], channel: u8, mode: u8) -> Result<Self, &'static str> {
        let allowed = if channel == 14 {
            0xf
        } else if channel <= 13 {
            0xfff
        } else {
            0xff0
        };
        let mut rates = Self {
            supported: 0,
            basic: 0,
        };
        while !ies.is_empty() {
            if ies.len() < 2 || ies[1] as usize > ies.len() - 2 {
                return Err("truncated rate IE");
            }
            let bytes = &ies[2..2 + ies[1] as usize];
            if matches!(ies[0], 1 | 50) {
                for &rate in bytes {
                    // HT/VHT BSS membership selectors are not bitrates.
                    if (rate == 0xff && mode >= 1) || (rate == 0xfe && mode >= 2) {
                        continue;
                    }
                    let bit = RATES
                        .iter()
                        .position(|&value| value == rate & 0x7f)
                        .map(|index| 1u16 << index)
                        .unwrap_or(0)
                        & allowed;
                    if rate & 0x80 != 0 && bit == 0 {
                        return Err("AP requires unsupported basic rate/PHY");
                    }
                    rates.supported |= bit;
                    if rate & 0x80 != 0 {
                        rates.basic |= bit;
                    }
                }
            }
            ies = &ies[2 + ies[1] as usize..];
        }
        if rates.supported == 0 {
            return Err("AP has no common rates");
        }
        if rates.basic == 0 {
            rates.basic = rates.supported & rates.supported.wrapping_neg();
        }
        Ok(rates)
    }
    pub fn elements(&self) -> Vec<u8> {
        RATES
            .iter()
            .enumerate()
            .filter_map(|(index, &rate)| {
                (self.supported & (1 << index) != 0).then_some(
                    rate | if self.basic & (1 << index) != 0 {
                        0x80
                    } else {
                        0
                    },
                )
            })
            .collect()
    }
    pub fn management_rate(&self, antenna: u32) -> u32 {
        // Select by bitrate, since firmware indices place 11M before 6M.
        let index = RATES
            .iter()
            .enumerate()
            .filter(|(index, _)| self.basic & (1 << index) != 0)
            .min_by_key(|(_, rate)| *rate)
            .map(|(index, _)| index)
            .unwrap();
        (antenna << 14)
            | if index < 4 {
                index as u32
            } else {
                0x100 | (index as u32 - 4)
            }
    }
    pub fn apply(&self, link: &mut [u8; 208]) {
        put32(link, 36, u32::from(self.basic & 0xf));
        put32(link, 40, u32::from(self.basic >> 4));
    }
    pub fn tlc(&self, version: u8, chains: u32) -> Result<[u8; 44], &'static str> {
        if version != 6 || chains == 0 || chains & !3 != 0 {
            return Err("unsupported TLC configuration");
        }
        let mut out = [0; 44];
        put32(&mut out, 0, 1); // station mask
        out[10] = chains as u8; // baseline; negotiated HT/VHT fields applied later
        put16(&mut out, 14, self.supported);
        put16(&mut out, 40, 4095);
        Ok(out)
    }
}
