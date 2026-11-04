// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B periodic DPK correction after actual slot0/TSSI completion.
//! Linux7.3-rc4 rtw8852b_rfk.c::_dpk_track; no RF/board authority here.
use super::{dpk, power};

pub(super) const BASE: u32 = 0x10000;
const THERMAL: u32 = 0x1c10;
const TXAGC: u32 = 0x1c60;
const TXAGC_TP: u32 = 0x1c04;
const TXDPD: u32 = 0x58d4;
const DPD_COM: u32 = 0x81c8;
const DPD_BND: u32 = 0x81b4;
const DPK_TRK: u32 = 0x80f0;
const TSSI_AVG: u32 = 0x5820;
const TSSI_TRK: u32 = 0x5818;

/// Exact logical AX BB register surface, translated by the retained native
/// adapter. No arbitrary register/RF/PMAC command is admitted by this helper.
pub(super) fn readable(address: u32) -> bool {
    address == DPK_TRK
        || [0, 0x2000].into_iter().any(|offset| {
            [THERMAL, TXAGC, TXAGC_TP, TXDPD, TSSI_AVG, TSSI_TRK]
                .into_iter()
                .any(|base| address == base + offset)
        })
        || [0, 0x100]
            .into_iter()
            .any(|offset| address == DPD_COM + offset || address == DPD_BND + offset)
}
pub(super) fn writable(address: u32) -> bool {
    matches!(address, DPD_BND | 0x82b4)
}
pub(super) trait Hw {
    /// Original current device/base/expanded tracking/power, not a callback.
    fn current(&mut self) -> Result<(), power::Error>;
    fn read_bb(&mut self, address: u32) -> Result<u32, power::Error>;
    /// Native RMW/readback must preserve bits outside mask and keep the
    /// current original source scopes around actual write publication.
    fn write_bb(&mut self, address: u32, mask: u32, value: u32) -> Result<(), power::Error>;
}

fn read(hw: &mut impl Hw, address: u32) -> Result<u32, power::Error> {
    let value = hw.read_bb(address)?;
    if value == u32::MAX {
        Err(power::Error::Access)
    } else {
        Ok(value)
    }
}

/// A signed expanded full-program measurement may cover only a subset of
/// actual9-bit PWSF values. Out-of-window computation refuses, never clamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Window {
    pub low: u16,
    pub high: u16,
}
impl Window {
    pub(super) fn valid(self) -> bool {
        self.low <= self.high && self.high <= 0x1ff
    }
    fn admits(self, value: u16) -> bool {
        self.valid() && (self.low..=self.high).contains(&value)
    }
}

/// Created by the actual Ready full Radio owner, not by a firmware enum or a
/// host station boolean. That owner completed/read back both TSSI paths and
/// installed DPK slot0 on channel1/20MHz before copying these results.
#[derive(Clone, Copy, Debug)]
pub(super) struct Inputs {
    paths: [dpk::Path; 2],
}
impl Inputs {
    pub(super) fn from_completed(paths: [dpk::Path; 2]) -> Option<Self> {
        paths
            .iter()
            .all(|p| p.thermal <= 63 && p.pwsf <= 511 && matches!(p.gain, 0x5b | 0x7f))
            .then_some(Self { paths })
    }
}

/// Linux DECLARE_EWMA(thermal,4,4): zero sensor samples are unavailable and
/// never replace an already sampled mean; the mean persists across peers.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Thermal(u32);
impl Thermal {
    pub(super) fn add(&mut self, sample: u8) {
        if sample == 0 {
            return;
        }
        let scaled = u32::from(sample) << 4;
        self.0 = if self.0 == 0 {
            scaled
        } else {
            ((self.0 << 2) - self.0 + scaled) >> 2
        };
    }
    pub(super) fn read(self) -> u8 {
        (self.0 >> 4) as u8
    }
}
#[derive(Clone, Copy, Debug)]
struct Sample {
    thermal: u8,
    txagc_rf: u8,
    txagc_bb: i8,
    txagc_tp: i8,
    txagc_offset: i8,
    hw_offset: bool,
    txdpd: bool,
}
#[derive(Debug)]
pub(super) struct Tracker {
    input: Inputs,
    average: [Thermal; 2],
    terminal: bool,
}
impl Tracker {
    pub(super) fn new(input: Inputs) -> Self {
        Self {
            input,
            average: [Thermal::default(); 2],
            terminal: false,
        }
    }
    pub(super) fn step(&mut self, hw: &mut impl Hw, window: Window) -> Result<(), power::Error> {
        if self.terminal || !window.valid() {
            return Err(power::Error::Terminal);
        }
        // An error can leave one path programmed; this owner never revives.
        self.terminal = true;
        hw.current()?;
        let disabled = read(hw, DPK_TRK)? & (1 << 31) != 0;
        let mut samples = [Sample {
            thermal: 0,
            txagc_rf: 0,
            txagc_bb: 0,
            txagc_tp: 0,
            txagc_offset: 0,
            hw_offset: false,
            txdpd: false,
        }; 2];
        let mut averages = self.average;
        for path in 0..2 {
            let offset = (path as u32) << 13;
            // Reconfirm the actual live TSSI mode, whose BB thermal source
            // differs from the non-TSSI RF trigger/delay producer.
            if read(hw, TSSI_AVG + offset)? & (1 << 31) == 0
                || read(hw, TSSI_TRK + offset)? & 0x18000000 != 0x18000000
            {
                return Err(power::Error::Access);
            }
            let thermal = ((read(hw, THERMAL + offset)? >> 24) & 63) as u8;
            averages[path].add(thermal);
            let txagc = read(hw, TXAGC + offset)?;
            samples[path] = Sample {
                thermal: averages[path].read(),
                txagc_rf: (txagc & 63) as u8,
                txagc_bb: (txagc >> 16) as u8 as i8,
                txagc_tp: (read(hw, TXAGC_TP + offset)? & 7) as i8,
                txagc_offset: (txagc >> 24) as u8 as i8,
                hw_offset: read(hw, DPD_COM + ((path as u32) << 8))? & (1 << 15) != 0,
                txdpd: read(hw, TXDPD + offset)? >> 28 != 0,
            };
        }
        let mut values = [None; 2];
        let mut initial_difference = 0i8;
        for (path, sample) in samples.iter().enumerate() {
            let original = self.input.paths[path];
            let delta = if sample.thermal == 0 {
                0
            } else {
                // `_dpk_track`: 2.4GHz delta * 3 / 2, 5GHz delta * 5 / 2.
                let delta = i16::from(original.thermal) - i16::from(sample.thermal);
                if original.a_band {
                    delta * 5 / 2
                } else {
                    delta * 3 / 2
                }
            } as i8;
            let offset = if sample.hw_offset {
                0
            } else {
                sample.txagc_offset
            };
            // Preserve source s8 assignment semantics, including the carried
            // ini_diff when the next path has no actual thermal/RF gain yet.
            if sample.txagc_rf != 0 && sample.thermal != 0 {
                initial_difference = offset.wrapping_add(delta);
            }
            let tp = if sample.txdpd {
                0
            } else {
                i16::from(sample.txagc_tp) - i16::from(sample.txagc_bb)
            };
            let value = (i32::from(original.pwsf) + i32::from(initial_difference) + i32::from(tp))
                as u16
                & 0x1ff;
            if !disabled && sample.txagc_rf != 0 {
                if !window.admits(value) {
                    return Err(power::Error::Access);
                }
                values[path] = Some(value);
            }
        }
        // Both path computations and measured window checks precede the
        // first change. Each native publication independently rechecks source.
        hw.current()?;
        for (path, value) in values.into_iter().enumerate() {
            if let Some(value) = value {
                let address = DPD_BND + ((path as u32) << 8);
                hw.current()?;
                hw.write_bb(
                    address,
                    0x01ff01ff,
                    u32::from(value) | u32::from(value) << 16,
                )?;
            }
        }
        hw.current()?;
        self.average = averages;
        self.terminal = false;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "rf_tracking_tests.rs"]
pub(super) mod tests;
