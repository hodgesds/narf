// SPDX-License-Identifier: GPL-2.0-or-later
//! Legacy rate selection and native four-series retry ownership. The adaptive
//! policy is NARF's; descriptor codes/feedback follow ath9k ar9002_mac.c/mac.h.

pub(super) const BITRATES: [u16; 12] = [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540];
// Increasing bitrate, unlike the IEEE bitmap's CCK-then-OFDM ordering.
const ORDER: [u8; 12] = [0, 1, 2, 4, 5, 3, 6, 7, 8, 9, 10, 11];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Series {
    pub rates: [u8; 4],
    pub tries: [u8; 4],
    pub basic: u8,
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_ar9285_rate_masks_and_bitrate_order() -> TestResult {
        for supported in 1..=0xfffu16 {
            let basic = supported & supported.wrapping_neg();
            let Some(control) = Control::new(supported, basic) else {
                return TestResult::Fail("valid legacy subset refused");
            };
            let series = control.series();
            if !series.valid(false) || series.basic != basic.trailing_zeros() as u8 {
                return TestResult::Fail("basic rate or retry geometry");
            }
            let fastest = BITRATES
                .iter()
                .enumerate()
                .filter(|(i, _)| supported & (1 << i) != 0)
                .map(|(_, b)| *b)
                .max()
                .unwrap();
            if BITRATES[usize::from(series.rates[0])] != fastest {
                return TestResult::Fail("CCK/OFDM bitmap index substituted for bitrate");
            }
            for slot in 0..4 {
                if series.tries[slot] != 0
                    && (supported & (1 << series.rates[slot]) == 0
                        || slot != 0
                            && BITRATES[usize::from(series.rates[slot])]
                                >= BITRATES[usize::from(series.rates[slot - 1])])
                {
                    return TestResult::Fail("retry escaped negotiated rate set/order");
                }
            }
        }
        for (supported, basic) in [(0, 1), (1, 0), (0x1000, 1), (1, 2)] {
            if Control::new(supported, basic).is_some() {
                return TestResult::Fail("invalid peer rate grant");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath9k/rates",
        smoke_ar9285_rate_masks_and_bitrate_order
    );
    fn smoke_ar9285_rate_terminal_feedback_and_bounded_recovery() -> TestResult {
        let mut control = Control::new(0xfff, 1).unwrap();
        if !control.complete(
            true,
            Feedback {
                rate: 9,
                retried: true,
                radio: true,
            },
        ) || control.series().rates[0] != 9
        {
            return TestResult::Fail("native fallback did not select actual terminal rate");
        }
        for _ in 0..7 {
            control.complete(
                true,
                Feedback {
                    rate: 9,
                    retried: false,
                    radio: true,
                },
            );
        }
        if control.series().rates[0] != 9 {
            return TestResult::Fail("unearned upward rate probe");
        }
        control.complete(
            true,
            Feedback {
                rate: 9,
                retried: false,
                radio: true,
            },
        );
        if control.series().rates[0] != 10 {
            return TestResult::Fail("eight native clean receipts did not probe next bitrate");
        }
        let before = control.series();
        control.complete(
            false,
            Feedback {
                rate: 7,
                retried: true,
                radio: false,
            },
        );
        if control.series() != before {
            return TestResult::Fail("FIFO/filtered feedback trained RF policy");
        }
        control.complete(
            false,
            Feedback {
                rate: 3,
                retried: true,
                radio: true,
            },
        );
        if control.series().rates[0] != 5 {
            return TestResult::Fail("CCK11 fallback ignored lower OFDM9");
        }
        let before = control.series();
        if control.complete(
            true,
            Feedback {
                rate: 12,
                retried: false,
                radio: true,
            },
        ) || before != control.series()
        {
            return TestResult::Fail("foreign terminal rate trained controller");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath9k/rates",
        smoke_ar9285_rate_terminal_feedback_and_bounded_recovery
    );
}
impl Series {
    pub(super) fn single(rate: usize, group: bool) -> Option<Self> {
        Some(Self {
            rates: [u8::try_from(rate).ok()?, 0, 0, 0],
            tries: [if group { 1 } else { 4 }, 0, 0, 0],
            basic: 0,
        })
    }
    pub(super) fn valid(self, group: bool) -> bool {
        if self.basic >= 12 || self.tries[0] == 0 {
            return false;
        }
        let mut stopped = false;
        for (&rate, &tries) in self.rates.iter().zip(&self.tries) {
            if tries == 0 {
                stopped = true;
                if rate != 0 {
                    return false;
                }
            } else if stopped || rate >= 12 || tries > 15 {
                return false;
            }
        }
        !group || self.tries == [1, 0, 0, 0]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Feedback {
    pub rate: u8,
    pub retried: bool,
    pub radio: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Control {
    supported: u16,
    basic: u8,
    current: u8,
    clean: u8,
}
impl Control {
    pub(super) fn new(supported: u16, basic: u16) -> Option<Self> {
        if supported == 0 || supported & !0xfff != 0 || basic == 0 || basic & !supported != 0 {
            return None;
        }
        Some(Self {
            supported,
            basic: *ORDER.iter().find(|&&i| basic & (1 << i) != 0)?,
            current: *ORDER.iter().rev().find(|&&i| supported & (1 << i) != 0)?,
            clean: 0,
        })
    }
    pub(super) fn basic(self) -> usize {
        usize::from(self.basic)
    }
    fn lower(self, rate: u8) -> Option<u8> {
        ORDER
            .iter()
            .copied()
            .filter(|&i| {
                self.supported & (1 << i) != 0
                    && BITRATES[usize::from(i)] < BITRATES[usize::from(rate)]
            })
            .next_back()
    }
    pub(super) fn series(self) -> Series {
        let mut series = Series {
            rates: [self.current, 0, 0, 0],
            tries: [4, 0, 0, 0],
            basic: self.basic,
        };
        let mut previous = self.current;
        for slot in 1..4 {
            let Some(rate) = self.lower(previous) else {
                break;
            };
            series.rates[slot] = rate;
            series.tries[slot] = 2;
            previous = rate;
        }
        series
    }
    // Only a matching terminal native DATA receipt calls this. RX traffic,
    // queued packets and pending/cancelled submissions never train the policy.
    pub(super) fn complete(&mut self, delivered: bool, receipt: Feedback) -> bool {
        if receipt.rate >= 12 || self.supported & (1 << receipt.rate) == 0 {
            return false;
        }
        if !receipt.radio {
            return true;
        }
        if !delivered {
            self.current = self.lower(receipt.rate).unwrap_or(receipt.rate);
            self.clean = 0;
        } else if receipt.retried {
            self.current = if receipt.rate == self.current {
                self.lower(receipt.rate).unwrap_or(receipt.rate)
            } else {
                receipt.rate
            };
            self.clean = 0;
        } else {
            self.clean += 1;
            if self.clean == 8 {
                self.current = ORDER
                    .iter()
                    .copied()
                    .find(|&i| {
                        self.supported & (1 << i) != 0
                            && BITRATES[usize::from(i)] > BITRATES[usize::from(self.current)]
                    })
                    .unwrap_or(self.current);
                self.clean = 0;
            }
        }
        true
    }
}
