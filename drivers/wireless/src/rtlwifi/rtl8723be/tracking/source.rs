// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2012 Realtek Corporation.
//! BE dm.c callback history and exact physical BBSWING program. No EE alias.
use super::super::{
    iqk,
    phy::{self, Path},
};
use super::tables::{CCK, OFDM};
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};
pub(super) const UP: [i8; 30] = [
    0, 0, 1, 2, 2, 2, 3, 3, 3, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14,
    15,
];
pub(super) const DOWN: [i8; 30] = [
    0, 0, 1, 2, 2, 2, 3, 3, 3, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 8, 8, 9, 9, 10, 10, 11, 12, 13, 14, 15,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct History {
    pub trigger: bool,
    pub thermal: u8,
    pub lck: u8,
    pub iqk: u8,
    pub average: [u8; 4],
    pub at: usize,
    pub delta: i8,
    pub last_delta: i8,
    pub offset: i8,
    pub cck_base: u8,
    pub ofdm_base: u8,
    pub cck_index: i8,
    pub ofdm_index: i8,
    pub swing_cck: u8,
    pub swing_ofdm: u8,
}
impl Default for History {
    fn default() -> Self {
        Self {
            trigger: false,
            thermal: 0,
            lck: 0,
            iqk: 0,
            average: [0; 4],
            at: 0,
            delta: 0,
            last_delta: 0,
            offset: 0,
            cck_base: 20,
            ofdm_base: 30,
            cck_index: 20,
            ofdm_index: 30,
            swing_cck: 0,
            swing_ofdm: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Update {
    pub average: u8,
    pub lck: bool,
    pub iqk: bool,
    pub write: bool,
    pub cck: u8,
    pub ofdm: u8,
}
impl History {
    /// Source conversion order is deliberate: raw s8 indices are copied to
    /// unsigned swing indices BEFORE the later software-index bounds.
    pub(crate) fn observe(&mut self, raw: u8, factory: u8) -> Option<Update> {
        if raw == 0 {
            return None;
        }
        if self.thermal == 0 {
            self.lck = raw;
            self.iqk = raw;
        }
        self.average[self.at] = raw;
        self.at = (self.at + 1) % 4;
        let (sum, count) = self
            .average
            .iter()
            .filter(|v| **v != 0)
            .fold((0u16, 0u16), |(s, n), v| (s + u16::from(*v), n + 1));
        let avg = (sum / count) as u8;
        let lck = avg.abs_diff(self.lck) >= 8;
        let iqk = avg.abs_diff(self.iqk) >= 8;
        if lck {
            self.lck = avg;
        }
        if avg != self.thermal {
            let index = usize::from(avg.abs_diff(factory).min(29));
            self.last_delta = self.delta;
            self.delta = if avg > factory {
                UP[index]
            } else {
                -DOWN[index]
            };
            self.offset = self.delta.wrapping_sub(self.last_delta);
            self.ofdm_index = self.ofdm_base.wrapping_add(self.offset as u8) as i8;
            self.cck_index = self.cck_base.wrapping_add(self.offset as u8) as i8;
            self.swing_cck = self.cck_index as u8;
            self.swing_ofdm = self.ofdm_index as u8;
            self.ofdm_index = self.ofdm_index.clamp(6, 36);
            self.cck_index = self.cck_index.clamp(0, 32);
        } else {
            self.offset = 0;
        }
        // The physical CCK setter clamps unsigned swing, not cck_index.
        let cck = self.swing_cck.min(32);
        let ofdm = self.swing_ofdm.min(42);
        Some(Update {
            average: avg,
            lck,
            iqk,
            write: self.offset != 0,
            cck,
            ofdm,
        })
    }
    pub(crate) fn written(&mut self, update: Update) {
        // set_power clamps swing_idx_cck itself. OFDM helper clamps its
        // local argument only; the original unsigned OFDM history persists.
        self.swing_cck = update.cck;
        self.cck_base = self.swing_cck;
        self.ofdm_base = self.swing_ofdm;
        self.thermal = update.average;
    }
    pub(crate) fn calibrated(&mut self, update: Update) {
        if update.iqk {
            self.iqk = update.average;
        }
    }
}
/// Exact masked output of set_iqk_matrix; ten-bit signed products have
/// the same masked low bits as the source's64-bit long OR0xfffffc00.
pub(crate) fn matrix(index: u8, x: u32, y: u32) -> (u32, u32, u32) {
    let value = OFDM[usize::from(index.min(42))];
    let d = (value >> 22) & 0x3ff;
    if x == 0 {
        return (value, 0, 0);
    }
    let signed = |v: u32| {
        if v & 0x200 != 0 {
            i64::from(v | 0xfffffc00)
        } else {
            i64::from(v)
        }
    };
    let x = signed(x);
    let y = signed(y);
    let a = ((x * i64::from(d)) >> 8) as u32 & 0x3ff;
    let c = ((y * i64::from(d)) >> 8) as u32 & 0x3ff;
    (
        (d << 22) | ((c & 0x3f) << 16) | a,
        (c & 0x3c0) >> 6,
        ((x * i64::from(d)) >> 7) as u32 & 1,
    )
}
pub(crate) fn program(io: &impl Io, update: Update, iq: [u32; 8]) -> Result<(), Error> {
    for (i, value) in CCK[usize::from(update.cck)].iter().enumerate() {
        io.write8(0xa22 + i as u16, *value)?;
    }
    let (full, afe, ecca) = matrix(update.ofdm, iq[0], iq[1]);
    phy::set_bb(io, iqk::ROFDM0_XATXIQIMBALANCE, u32::MAX, full)?;
    phy::set_bb(io, iqk::ROFDM0_XCTXAFE, 0xf0000000, afe)?;
    phy::set_bb(io, iqk::ROFDM0_ECCATHRESHOLD, 1 << 24, ecca)?;
    for (i, byte) in CCK[usize::from(update.cck)].iter().enumerate() {
        if io.read8(0xa22 + i as u16)? != *byte {
            return Err(Error::Readback);
        }
    }
    if io.read32(iqk::ROFDM0_XATXIQIMBALANCE)? != full
        || io.read32(iqk::ROFDM0_XCTXAFE)? >> 28 != afe
        || (io.read32(iqk::ROFDM0_ECCATHRESHOLD)? >> 24) & 1 != ecca
    {
        return Err(Error::Readback);
    }
    Ok(())
}
pub(crate) async fn trigger(io: &impl Io) -> Result<(), Error> {
    phy::set_rf(io, Path::A, 0x42, 3 << 16, 3).await
}
pub(crate) async fn sample(io: &impl Io) -> Result<u8, Error> {
    Ok(phy::get_rf(io, Path::A, 0x42, 0xfc00).await? as u8)
}
