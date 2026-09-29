//! WMM negotiation, AP EDCA parameters and four unaggregated TX queues.
//! Firmware AC order is BK, BE, VI, VO (fw/api/mac.h).

use super::boot_context::{put16, put32};

pub const TIDS: [u8; 4] = [1, 0, 4, 6];
pub const INFORMATION_IE: [u8; 9] = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AccessCategory {
    pub cw_min: u16,
    pub cw_max: u16,
    pub aifs: u8,
    pub txop_us: u16,
    pub admission: bool,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub ac: [AccessCategory; 4],
}
impl Default for Parameters {
    fn default() -> Self {
        let ac = |cw_min, cw_max, aifs, txop_us| AccessCategory {
            cw_min,
            cw_max,
            aifs,
            txop_us,
            admission: false,
        };
        Self {
            ac: [
                ac(15, 1023, 7, 0),
                ac(15, 1023, 3, 0),
                ac(7, 15, 2, 3008),
                ac(3, 7, 2, 1504),
            ],
        }
    }
}
impl Parameters {
    /// Reject malformed/duplicate WMM elements and invalid EDCA intervals.
    pub fn parse(mut ies: &[u8]) -> Result<Option<Self>, &'static str> {
        let mut result = None;
        while !ies.is_empty() {
            if ies.len() < 2 || ies[1] as usize > ies.len() - 2 {
                return Err("truncated BSS IE");
            }
            let body = &ies[2..2 + ies[1] as usize];
            if ies[0] == 221 && body.starts_with(&[0, 0x50, 0xf2, 2]) {
                if result.is_some() || body.len() < 7 || body[5] != 1 {
                    return Err("invalid WMM IE");
                }
                let mut params = Self::default();
                match body[4] {
                    0 if body.len() == 7 => {}
                    1 if body.len() == 24 => {
                        let mut seen = 0u8;
                        for raw in body[8..].chunks_exact(4) {
                            let index = [1, 0, 2, 3][((raw[0] >> 5) & 3) as usize];
                            if seen & (1 << index) != 0
                                || raw[0] & 0xf < 2
                                || raw[1] & 0xf > raw[1] >> 4
                            {
                                return Err("invalid WMM contention parameters");
                            }
                            seen |= 1 << index;
                            let txop = u16::from_le_bytes([raw[2], raw[3]])
                                .checked_mul(32)
                                .ok_or("WMM TXOP exceeds firmware field")?;
                            params.ac[index] = AccessCategory {
                                cw_min: (1u16 << (raw[1] & 0xf)) - 1,
                                cw_max: (1u16 << (raw[1] >> 4)) - 1,
                                aifs: raw[0] & 0xf,
                                txop_us: txop,
                                admission: raw[0] & 0x10 != 0,
                            };
                        }
                    }
                    _ => return Err("unsupported WMM IE"),
                }
                result = Some(params);
            }
            ies = &ies[2 + ies[1] as usize..];
        }
        Ok(result)
    }

    pub fn apply(&self, link: &mut [u8; 208]) {
        put32(link, 56, 1); // MAC_QOS_FLG_UPDATE_EDCA
        for (index, ac) in self.ac.iter().enumerate() {
            let offset = 60 + index * 8;
            put16(link, offset, ac.cw_min);
            put16(link, offset + 2, ac.cw_max);
            link[offset + 4] = ac.aifs;
            put16(link, offset + 6, ac.txop_us);
        }
    }

    /// IPv4/IPv6 DSCP, with EF promoted to voice. Unsupported admission
    /// control downgrades to the next permitted category, never bypasses ACM.
    pub fn classify(&self, ethernet: &[u8]) -> Option<usize> {
        let dscp = match ethernet.get(12..14)? {
            [8, 0] if ethernet.len() >= 34 && ethernet[14] >> 4 == 4 => ethernet[15] >> 2,
            [0x86, 0xdd] if ethernet.len() >= 54 && ethernet[14] >> 4 == 6 => {
                ((ethernet[14] & 0xf) << 2) | (ethernet[15] >> 6)
            }
            _ => 0,
        };
        let priority = if dscp == 46 { 6 } else { dscp >> 3 };
        let wanted = match priority {
            1 | 2 => 0,
            4 | 5 => 2,
            6 | 7 => 3,
            _ => 1,
        };
        self.admitted(wanted)
    }
    pub fn admitted(&self, wanted: usize) -> Option<usize> {
        (0..=wanted.min(3))
            .rev()
            .find(|&index| !self.ac[index].admission)
    }
}
