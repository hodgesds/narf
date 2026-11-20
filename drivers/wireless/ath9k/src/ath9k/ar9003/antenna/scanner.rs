// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! Linux ath9k/antenna.c distinct group2 and group3 programs, including complete
//! normal/quick scan. RSSI is signed RSSI_ctl, never combined RSSI. This
//! module decides only: its caller owns current qualification, physical
//! register transactions, readback and atomic software-state commit.
use super::{Config, Observation};
use crate::ath9k::packet::Error;

const SUB: u8 = 0;
const LNA2: u8 = 1;
const LNA1: u8 = 2;
const ADD: u8 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Group {
    Ar9485,
    Ar9565,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Scanner {
    group: Group,
    count: u16,
    total: u16,
    main_total: i32,
    alt_total: i32,
    main_recv: u16,
    alt_recv: u16,
    scan: bool,
    scan_not_start: bool,
    lna1: i32,
    lna2: i32,
    add: i32,
    sub: i32,
    first: i32,
    second: i32,
    third: i32,
    ratio: i32,
    ratio2: i32,
    alt_good: bool,
    quick: u8,
    main: u8,
    first_conf: u8,
    second_conf: u8,
    first_ratio: bool,
    second_ratio: bool,
    start_ms: u64,
    low: i32,
    bias: u8,
}
impl Scanner {
    pub(super) fn new(low: u8, bias: u8) -> Self {
        Self {
            group: Group::Ar9485,
            count: 95,
            total: 0,
            main_total: 0,
            alt_total: 0,
            main_recv: 0,
            alt_recv: 0,
            scan: false,
            scan_not_start: false,
            lna1: 0,
            lna2: 0,
            add: 0,
            sub: 0,
            first: 0,
            second: 0,
            third: 0,
            ratio: 0,
            ratio2: 0,
            alt_good: false,
            quick: 0,
            main: 0,
            first_conf: 0,
            second_conf: 0,
            first_ratio: false,
            second_ratio: false,
            start_ms: 0,
            low: i32::from(low),
            bias,
        }
    }
    pub(super) fn new_9565() -> Self {
        Self {
            group: Group::Ar9565,
            ..Self::new(0, 0)
        }
    }
    fn switch_delta(&self) -> i32 {
        match self.group {
            Group::Ar9485 => -1,
            Group::Ar9565 => 3,
        }
    }
    /// Caller works on a copy; failure cannot advance retained history.
    pub(super) fn observe(
        &mut self,
        mut config: Config,
        observed: Observation,
        now_ms: u64,
    ) -> Result<Option<Config>, Error> {
        let main = i32::from(observed.ctl[0] as i8);
        let alt = i32::from(observed.ctl[1] as i8);
        let rx_conf = (observed.ctl[2] >> 4) & 3;
        let main_conf = (observed.ctl[2] >> 2) & 3;
        (self.ratio, self.ratio2) = if alt >= self.low { (30, 20) } else { (50, 50) };
        if main > 0 && alt > 0 {
            self.total = self.total.checked_add(1).ok_or(Error::Descriptor)?;
            self.main_total = self.main_total.checked_add(main).ok_or(Error::Descriptor)?;
            self.alt_total = self.alt_total.checked_add(alt).ok_or(Error::Descriptor)?;
            let count = if main_conf == rx_conf {
                &mut self.main_recv
            } else {
                &mut self.alt_recv
            };
            *count = count.checked_add(1).ok_or(Error::Descriptor)?;
        }
        let short = self.short_scan(now_ms);
        if (self.total < 512 || observed.more_aggr) && !short {
            return Ok(None);
        }
        let (ratio, main, alt) = if self.total == 0 {
            (0, 0, 0)
        } else {
            let n = i32::from(self.total);
            (
                i32::from(self.alt_recv) * 100 / n,
                self.main_total / n,
                self.alt_total / n,
            )
        };
        let old_main = config.main;
        let old_alt = config.alt;
        self.count = self.count.checked_add(1).ok_or(Error::Descriptor)?;
        if self.count == 100 {
            self.alt_good = ratio > self.ratio;
            if self.alt_good {
                self.alt_good_scan(config, main);
            }
            self.count = 0;
            self.scan = true;
            self.scan_not_start = true;
        }
        let done = !self.scan && self.try_switch(&mut config, ratio, alt, main, old_main, old_alt);
        // Both groups use scan delta -9; final switches use -1/+3. Preserve source
        // strict comparisons and its switch-before-delta-check ordering.
        if !done && (self.scan || alt >= main - 9) {
            if !self.scan_not_start {
                self.try_scan(&mut config, old_alt, alt, main);
            } else if !self.alt_good {
                self.scan_not_start = false;
                if old_main == LNA2 {
                    config.main = LNA2;
                    config.alt = LNA1;
                } else if old_main == LNA1 {
                    config.main = LNA1;
                    config.alt = LNA2;
                }
            } else {
                self.quick_scan(&mut config, main, alt, ratio);
                self.quick = self.quick.checked_add(1).ok_or(Error::Descriptor)?;
            }
        }
        self.fast_bias(&mut config, ratio);
        self.start_ms = now_ms;
        self.total = 0;
        self.main_total = 0;
        self.alt_total = 0;
        self.main_recv = 0;
        self.alt_recv = 0;
        Ok(Some(config))
    }
    fn short_scan(&self, now_ms: u64) -> bool {
        if !self.scan || !self.alt_good {
            return false;
        }
        let elapsed = now_ms.wrapping_sub(self.start_ms);
        // time_after(), including the strictly-greater-than boundary.
        if elapsed > 50 && elapsed < (1u64 << 63) {
            return true;
        }
        self.total == 256 && i32::from(self.alt_recv) * 100 / i32::from(self.total) < self.ratio
    }
    fn alt_check(&self, c: Config, ratio: i32, alt: i32, main: i32) -> bool {
        if alt < 4 || alt < self.low {
            return false;
        }
        let (lna2, lna1) = match self.group {
            Group::Ar9485 => (-5, -2),
            Group::Ar9565 => (-3, 3),
        };
        (c.main == LNA2 && c.alt == LNA1 && alt >= main + lna2)
            || (c.main == LNA1 && c.alt == LNA2 && alt >= main + lna1)
            || ratio > self.ratio
    }
    fn try_switch(
        &self,
        c: &mut Config,
        ratio: i32,
        alt: i32,
        main: i32,
        old_main: u8,
        old_alt: u8,
    ) -> bool {
        if self.alt_check(*c, ratio, alt, main) {
            if old_alt == LNA2 {
                c.main = LNA2;
                c.alt = LNA1;
            } else if old_alt == LNA1 {
                c.main = LNA1;
                c.alt = LNA2;
            }
            return true;
        }
        if old_alt != LNA1 && old_alt != LNA2 {
            if old_main == LNA2 {
                c.alt = LNA1;
            } else if old_main == LNA1 {
                c.alt = LNA2;
            }
            return true;
        }
        false
    }
    fn alt_good_scan(&mut self, c: Config, main: i32) {
        self.quick = 0;
        if c.main == LNA2 {
            self.lna2 = main;
        } else if c.main == LNA1 {
            self.lna1 = main;
        }
        let next = match (c.main << 4) | c.alt {
            0x10 => Some((SUB, ADD, LNA1)),
            0x20 => Some((SUB, ADD, LNA2)),
            0x21 => Some((LNA2, SUB, ADD)),
            0x12 => Some((LNA1, SUB, ADD)),
            0x13 => Some((ADD, SUB, LNA1)),
            0x23 => Some((ADD, SUB, LNA2)),
            _ => None,
        };
        if let Some((main, first, second)) = next {
            self.main = main;
            self.first_conf = first;
            self.second_conf = second;
        }
    }
    fn ratio_better(&self, ratio: i32, main: i32, alt: i32) -> bool {
        if self.total <= 50 {
            return false;
        }
        let (max, min) = match self.main {
            LNA1 => (-4, 2),
            LNA2 => (-2, 2),
            _ => (-4, 0),
        };
        alt > main + min || ratio >= self.ratio2 && alt >= self.low && alt > main + max
    }
    fn quick_scan(&mut self, c: &mut Config, main: i32, alt: i32, ratio: i32) {
        match self.quick {
            0 => {
                c.main = self.main;
                c.alt = self.first_conf;
            }
            1 => {
                c.main = self.main;
                c.alt = self.second_conf;
                self.first = main;
                self.second = alt;
                self.first_ratio = self.ratio_better(ratio, main, alt);
            }
            2 => {
                self.alt_good = false;
                self.scan_not_start = false;
                self.scan = false;
                self.first = main;
                self.third = alt;
                match self.second_conf {
                    LNA1 => self.lna1 = alt,
                    LNA2 => self.lna2 = alt,
                    ADD if self.main == LNA2 => self.lna2 = main,
                    ADD if self.main == LNA1 => self.lna1 = main,
                    _ => (),
                }
                c.main = if self.lna2 > self.lna1 + self.switch_delta() {
                    LNA2
                } else {
                    LNA1
                };
                self.second_ratio = self.ratio_better(ratio, main, alt);
                let chosen = if self.first_ratio && self.second_ratio {
                    if self.second > self.third {
                        self.first_conf
                    } else {
                        self.second_conf
                    }
                } else if self.first_ratio {
                    self.first_conf
                } else if self.second_ratio {
                    self.second_conf
                } else {
                    self.main
                };
                c.alt = if matches!(chosen, LNA1 | LNA2) {
                    if c.main == LNA2 {
                        LNA1
                    } else {
                        LNA2
                    }
                } else {
                    chosen
                };
            }
            _ => (),
        }
    }
    fn try_scan(&mut self, c: &mut Config, old_alt: u8, alt: i32, main: i32) {
        match old_alt {
            LNA2 => {
                self.lna2 = alt;
                self.lna1 = main;
                self.scan = true;
                c.main = LNA1;
                c.alt = ADD;
            }
            LNA1 => {
                self.lna1 = alt;
                self.lna2 = main;
                self.scan = true;
                c.main = LNA2;
                c.alt = ADD;
            }
            ADD => {
                self.add = alt;
                self.scan = true;
                c.alt = SUB;
            }
            SUB => {
                self.sub = alt;
                self.scan = false;
                let (selected, other) = if self.lna2 > self.lna1 + self.switch_delta() {
                    (LNA2, self.lna1)
                } else {
                    (LNA1, self.lna2)
                };
                c.main = selected;
                c.alt = if self.add > other && self.add > self.sub {
                    ADD
                } else if self.sub > other {
                    SUB
                } else if selected == LNA2 {
                    LNA1
                } else {
                    LNA2
                };
            }
            _ => (),
        }
    }
    fn fast_bias(&self, c: &mut Config, ratio: i32) {
        c.main_gain = false;
        c.alt_gain = false;
        if self.group == Group::Ar9565 {
            c.bias = match (c.main << 4) | c.alt {
                0x01 | 0x03 | 0x30 | 0x32 => 1,
                0x02 => 0x39,
                0x10 | 0x13 => 2,
                0x12 => 0x3f,
                0x20 | 0x21 | 0x23 => 3,
                0x31 => 6,
                _ => c.bias,
            };
            return;
        }
        match (c.main << 4) | c.alt {
            0x01 | 0x02 | 0x03 | 0x12 | 0x21 | 0x30 | 0x31 | 0x32 => c.bias = 1,
            0x10 | 0x13 | 0x20 | 0x23 => {
                c.bias = if !self.scan && ratio > self.ratio {
                    1
                } else {
                    2
                }
            }
            _ => (),
        }
        if self.bias != 0 {
            c.bias = self.bias;
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "scanner_tests.rs"]
mod tests;
