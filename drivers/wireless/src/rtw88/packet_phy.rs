// SPDX-License-Identifier: GPL-2.0-or-later
//! One original32-byte native PHY-status record, Linux rtw8821c/rtw8822c
//! query_phy_status_page{0,1}. This carries no peer/key/radio authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Chip {
    C21,
    C22,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) page: u8,
    /// Source RTW bandwidth code (0=20,1=40,2=80).
    pub(super) bandwidth: u8,
    /// C21 has no channel field. Never reinterpret C22's byte on that chip.
    pub(super) channel: Option<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Length,
    Page,
    Mode,
}
impl Evidence {
    pub(super) fn initial_channel(self) -> bool {
        self.page <= 1 && self.bandwidth == 0 && self.channel.is_none_or(|c| c == 1)
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_rtw88_native_phy_literal_chip_pages_offsets_and_extent() -> TestResult {
        const BANDWIDTH: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2];
        for chip in [Chip::C21, Chip::C22] {
            for (rxsc, bw) in BANDWIDTH.into_iter().enumerate() {
                let mut p = [0; 32];
                p[0] = 1;
                p[5] = (rxsc as u8) << 4;
                p[6] = 1;
                let expected = Evidence {
                    page: 1,
                    bandwidth: bw,
                    channel: if chip == Chip::C21 { None } else { Some(1) },
                };
                if parse(chip, 19, &p) != Ok(expected) {
                    return TestResult::Fail("literal PHY RXSC map or chip channel decoding");
                }
            }
        }
        for mode in 0..4 {
            let mut p = [0; 32];
            p[0] = 1;
            p[6] = 1;
            p[15] = mode << 4;
            let c21 = parse(Chip::C21, 19, &p);
            if mode == 3 {
                if c21 != Err(Error::Mode) {
                    return TestResult::Fail("reserved C21 PHY RF_MODE accepted");
                }
            } else if c21
                != Ok(Evidence {
                    page: 1,
                    bandwidth: mode,
                    channel: None,
                })
            {
                return TestResult::Fail("C21 zeroRXSC did not use RF_MODE");
            }
            if parse(Chip::C22, 19, &p)
                != Ok(Evidence {
                    page: 1,
                    bandwidth: 0,
                    channel: Some(1),
                })
            {
                return TestResult::Fail("C22 borrowed C21 RF_MODE instead of retained20");
            }
        }
        let mut p = [0; 32];
        p[6] = 6;
        if parse(Chip::C21, 3, &p)
            != Ok(Evidence {
                page: 0,
                bandwidth: 0,
                channel: None,
            })
            || parse(Chip::C22, 3, &p)
                != Ok(Evidence {
                    page: 0,
                    bandwidth: 0,
                    channel: Some(6),
                })
            || parse(Chip::C21, 19, &p) != Err(Error::Page)
        {
            return TestResult::Fail("native CCK/HT page mismatch or invented C21 channel");
        }
        for len in [0, 1, 31, 33, 64] {
            let b = alloc::vec![0;len];
            if parse(Chip::C22, 19, &b) != Err(Error::Length) {
                return TestResult::Fail("truncated/duplicate PHY record admitted");
            }
        }
        for shift in 0..4 {
            let mut d = [0; 24];
            d[..4].copy_from_slice(&(64u32 | (4 << 16) | (1 << 26) | (shift << 24)).to_le_bytes());
            d[12] = 19;
            if crate::rtw88::packet_format::receive_profile(&d, true).is_err()
                || crate::rtw88::packet_format::phy_status(&d)
                    != Some(24 + shift as usize..56 + shift as usize)
            {
                return TestResult::Fail(
                    "PHY did not begin after descriptor shift before driver-info payload",
                );
            }
            d[..4].copy_from_slice(&(64u32 | (4 << 16) | (shift << 24)).to_le_bytes());
            if crate::rtw88::packet_format::phy_status(&d).is_some() {
                return TestResult::Fail("absent PHYST invented PHY evidence");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw88/ht/phy",
        smoke_rtw88_native_phy_literal_chip_pages_offsets_and_extent
    );
}

pub(super) fn parse(chip: Chip, rate: u8, bytes: &[u8]) -> Result<Evidence, Error> {
    if bytes.len() != 32 {
        return Err(Error::Length);
    }
    let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let page = bytes[0] & 15;
    let bandwidth = match page {
        0 if rate < 4 => 0,
        1 if rate >= 4 => {
            let rxsc = if rate < 12 {
                (word(4) >> 8) & 15
            } else {
                (word(4) >> 12) & 15
            };
            match rxsc {
                0 => match chip {
                    Chip::C21 => {
                        let mode = ((word(12) >> 28) & 3) as u8;
                        if mode == 3 {
                            return Err(Error::Mode);
                        }
                        mode
                    }
                    Chip::C22 => 0,
                }, // retained native owner is fixed20MHz
                1..=8 => 0,
                9..=12 => 1,
                _ => 2,
            }
        }
        _ => return Err(Error::Page),
    };
    Ok(Evidence {
        page,
        bandwidth,
        channel: match chip {
            Chip::C21 => None,
            Chip::C22 => Some(((word(4) >> 16) & 255) as u8),
        },
    })
}
