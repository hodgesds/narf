//! Checked WMM v1 information/parameter elements. IEEE wire facts only;
//! selecting queues, admission control, power and association are driver duties.

/// Station Information IE: no U-APSD queues and no maximum service period.
pub const INFORMATION: [u8; 9] = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Duplicate,
    Format,
    AccessCategory,
}
/// Raw AP contention facts, without hardware-specific units or permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ac {
    pub aifsn: u8,
    pub ecw_min: u8,
    pub ecw_max: u8,
    /// In32-microsecond units, as transmitted by the AP.
    pub txop: u16,
    pub admission_control: bool,
}
impl Ac {
    // Saturate manually authored out-of-protocol rows rather than shifting
    // out of range. Parsed exponents are always0..15.
    pub fn cw_min(self) -> u16 {
        window(self.ecw_min)
    }
    pub fn cw_max(self) -> u16 {
        window(self.ecw_max)
    }
}
fn window(exponent: u8) -> u16 {
    1u32.checked_shl(u32::from(exponent))
        .unwrap_or(u32::MAX)
        .saturating_sub(1)
        .min(u32::from(u16::MAX)) as u16
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    /// Canonical ACI order: BE, BK, VI, VO, independent of IE row order.
    pub ac: [Ac; 4],
    pub parameter_set_count: u8,
    pub uapsd: bool,
}
impl Parameters {
    /// Parse an entire bounded IE stream. An Information IE alone returns
    /// None. Duplicate WMM elements, including Info+Parameter, are rejected.
    /// ECW0 and ACM are protocol facts; drivers decide whether to admit them.
    pub fn parse(mut ies: &[u8]) -> Result<Option<Self>, Error> {
        if ies.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut found = false;
        let mut result = None;
        while !ies.is_empty() {
            let header = ies.get(..2).ok_or(Error::Bounds)?;
            let end = 2 + usize::from(header[1]);
            let body = ies.get(2..end).ok_or(Error::Bounds)?;
            if header[0] == 221 && body.starts_with(&[0, 0x50, 0xf2, 2]) {
                if found {
                    return Err(Error::Duplicate);
                }
                found = true;
                if body.get(5) != Some(&1) || body.get(6).is_none_or(|q| q & 0x70 != 0) {
                    return Err(Error::Format);
                }
                match body.get(4) {
                    Some(0) if body.len() == 7 => {}
                    Some(1) if body.len() == 24 && body[7] == 0 => {
                        let empty = Ac {
                            aifsn: 0,
                            ecw_min: 0,
                            ecw_max: 0,
                            txop: 0,
                            admission_control: false,
                        };
                        let mut ac = [empty; 4];
                        let mut seen = 0u8;
                        for row in body[8..].chunks_exact(4) {
                            let index = usize::from((row[0] >> 5) & 3);
                            let min = row[1] & 15;
                            let max = row[1] >> 4;
                            if row[0] & 0x80 != 0
                                || row[0] & 15 < 2
                                || min > max
                                || seen & (1 << index) != 0
                            {
                                return Err(Error::AccessCategory);
                            }
                            seen |= 1 << index;
                            ac[index] = Ac {
                                aifsn: row[0] & 15,
                                ecw_min: min,
                                ecw_max: max,
                                txop: u16::from_le_bytes([row[2], row[3]]),
                                admission_control: row[0] & 16 != 0,
                            };
                        }
                        if seen != 15 {
                            return Err(Error::AccessCategory);
                        }
                        result = Some(Self {
                            ac,
                            parameter_set_count: body[6] & 15,
                            uapsd: body[6] & 0x80 != 0,
                        });
                    }
                    _ => return Err(Error::Format),
                }
            }
            ies = &ies[end..];
        }
        Ok(result)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "wmm_tests.rs"]
mod tests;
