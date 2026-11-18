// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A SCC RFK context/reload and firmware-versioned notifications.
//! Source: rtw8922a_rfk.c::chlk_reload/ktbl_sel, fw.c::rf_pre_ntfy,
//! ::rf_pre_ntfy_mcc, fw.h packed structs and phy.c::pre_ntfy_and_wait.
//! A zero record is source-initialized software state, never a hardware fact.
use super::{
    be_features::{Features, MccNotify, PreNotify},
    be_rfk::{self, Report},
    Error, Interface,
};
use crate::rtw89::{channel_be, operating_channel_c::Profile};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Record {
    channel: u8,
    band: u8,
    bandwidth: u8,
    rf18: u32,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Path {
    records: [Record; 3],
    selected: usize,
}
/// Source software state after rtw8922a_rfk_init's memset. Only a completed
/// checked reload can claim a programmed context. No RF permission is minted.
#[derive(Default)]
pub(in crate::rtw89) struct Context {
    paths: [Path; 2],
    programmed: Option<(Profile, [u8; 4])>,
    busy: bool,
}
impl Context {
    pub(in crate::rtw89) fn matches(&self, profile: Profile, features: Features) -> bool {
        !self.busy && self.programmed == Some((profile, features.version()))
    }
    /// Single-PHY, non-MLO source post_set_channel_rf reload. Source lookup
    /// first reuses an equivalent (ch, band, BW) entry; in SCC every other
    /// entry is unused by the sole active channel, so the first is available.
    /// MCC-v1 shares path A's table but keeps independent path selectors.
    ///
    /// # Safety
    /// Actual qualified RTL8922A after full tables/RFK software initialization
    /// and source set_channel RF, with current authority for `profile` on the
    /// one active SCC channel. Interface must enforce this at every effect.
    /// Caller terminalizes the radio on any error or dropped pending future.
    pub(in crate::rtw89) async unsafe fn reload(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        features: Features,
    ) -> Result<(), Error> {
        if self.busy {
            return Err(Error::Terminal);
        }
        let rf18 = channel_be::set_channel_rf_value(profile).ok_or(Error::Policy)?;
        io.admit()?;
        self.busy = true;
        self.programmed = None;
        let record = Record {
            channel: profile.center(),
            band: profile.band() as u8,
            bandwidth: profile.width() as u8,
            rf18,
        };
        let mut selected = [0; 2];
        for (path, index) in selected.iter_mut().enumerate() {
            let source = if features.mcc == MccNotify::V1 {
                0
            } else {
                path
            };
            *index = self.paths[source]
                .records
                .iter()
                .position(|old| {
                    (old.channel, old.band, old.bandwidth)
                        == (record.channel, record.band, record.bandwidth)
                })
                .unwrap_or(0);
            self.paths[source].records[*index] = record;
            self.paths[path].selected = *index;
        }
        for (path, index) in selected.into_iter().enumerate() {
            let coef = 0x28104 + path as u32 * 0x100;
            let cfir = 0x28154 + path as u32 * 0x100;
            field(io, coef, 0x8000_0000, 1)?;
            field(io, coef, 3, index as u32)?;
            field(io, coef, 0x300, index as u32)?;
            io.admit()?;
            io.rf_write(path as u8, 1, 0x000e_0000, 4 | index as u32)
                .await?;
            let tmp = read_field(io, coef, 1)?;
            field(io, cfir, 8, tmp)?;
            let tmp = read_field(io, coef, 2)?;
            field(io, cfir, 0x20, tmp)?;
        }
        io.admit()?;
        self.programmed = Some((profile, features.version()));
        self.busy = false;
        Ok(())
    }
    fn selected(&self, path: usize) -> Record {
        self.paths[path].records[self.paths[path].selected]
    }
    fn pre_body(&self, features: Features) -> Option<Body> {
        let length = match features.pre {
            PreNotify::V0 => 128,
            PreNotify::V1 => 76,
            PreNotify::V2 => 84,
            PreNotify::Disabled => return None,
        };
        let mut body = Body::new(length);
        // Packed common.dbcc is [path][table]; mlo=NOT_SUPPORT, PHY0.
        for path in 0..2 {
            for table in 0..3 {
                let entry = self.paths[path].records[table];
                body.word((path * 3 + table) * 4, u32::from(entry.channel));
                body.word(24 + (path * 3 + table) * 4, u32::from(entry.band));
            }
            body.word(52 + path * 4, u32::from(self.selected(path).channel));
            body.word(60 + path * 4, u32::from(self.selected(path).band));
            if features.pre == PreNotify::V2 {
                body.word(76 + path * 4, u32::from(self.selected(path).bandwidth));
            }
        }
        body.word(48, 1); // MLO_DBCC_NOT_SUPPORT, source enum value.
        if features.pre == PreNotify::V0 {
            let selected = self.selected(0);
            body.word(72, u32::from(selected.band));
            body.word(76, u32::from(selected.bandwidth));
            body.word(80, u32::from(selected.channel));
            // drv_mode, mlo_1_1, unused MLO ch/band are source memset zeros.
        }
        Some(body)
    }
    fn mcc_body(&self, features: Features) -> Option<Body> {
        let mut body = Body::new(match features.mcc {
            MccNotify::Disabled => return None,
            MccNotify::V0 => 36,
            MccNotify::V1 => 30,
        });
        if features.mcc == MccNotify::V0 {
            for table in 0..3 {
                for path in 0..2 {
                    body.word((table * 2 + path) * 4, self.paths[path].records[table].rf18);
                }
            }
            for path in 0..2 {
                body.word(24 + path * 4, self.selected(path).rf18);
            }
            body.word(32, 1);
        } else {
            for table in 0..3 {
                body.word(table * 4, self.paths[0].records[table].rf18);
            }
            for path in 0..2 {
                body.word(
                    12 + path * 4,
                    self.paths[0].records[self.paths[path].selected].rf18,
                );
            }
            body.word(20, 1);
            body.bytes[29] = self.paths[0].selected as u8;
        }
        Some(body)
    }
}
struct Body {
    bytes: [u8; 128],
    length: usize,
}
impl Body {
    fn new(length: usize) -> Self {
        Self {
            bytes: [0; 128],
            length,
        }
    }
    fn word(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
fn read_field(io: &mut impl Interface, address: u32, mask: u32) -> Result<u32, Error> {
    io.admit()?;
    Ok((io.read32(address)? & mask) >> mask.trailing_zeros())
}
fn field(io: &mut impl Interface, address: u32, mask: u32, value: u32) -> Result<(), Error> {
    let original = read_field(io, address, u32::MAX)?;
    io.admit()?;
    io.write32(
        address,
        (original & !mask) | ((value << mask.trailing_zeros()) & mask),
    )?;
    Ok(())
}
/// The source pre-notification/report operation. V0 reads the actual live
/// coefficient selectors and RR_CFGCH words; no factory/default surrogate is
/// accepted. Caller records/checks this report before invoking `mcc`.
pub(in crate::rtw89) async fn pre(
    io: &mut impl Interface,
    features: Features,
    context: &Context,
    rfe: u8,
) -> Result<Option<Report>, Error> {
    if context.busy {
        return Err(Error::Terminal);
    }
    io.admit()?;
    let mut report = None;
    if let Some(mut body) = context.pre_body(features) {
        if features.pre == PreNotify::V0 {
            body.word(84, read_field(io, 0x28104, 3)?);
            body.word(88, read_field(io, 0x28204, 3)?);
            io.admit()?;
            body.word(92, io.rf_read(0, 0x18, 0xfffff).await?);
            io.admit()?;
            body.word(96, io.rf_read(1, 0x18, 0xfffff).await?);
            body.word(104, u32::from(rfe));
        }
        let observed = be_rfk::run(io, be_rfk::FUNC_PRE_NOTIFY, body.bytes(), 5).await?;
        // Preserve the non-OK report for the caller's record before refusal.
        if be_rfk::check(observed).is_err() {
            return Ok(Some(observed));
        }
        report = Some(observed);
    }
    Ok(report)
}
/// The subsequent source MCC notification has its own H2C class and no
/// report wait. Keep it separate so an MCC transport error cannot erase the
/// already observed PRE report from the retained calibration record.
pub(in crate::rtw89) async fn mcc(
    io: &mut impl Interface,
    features: Features,
    context: &Context,
) -> Result<(), Error> {
    if context.busy {
        return Err(Error::Terminal);
    }
    if let Some(body) = context.mcc_body(features) {
        io.admit()?;
        io.h2c(2, 0xa, 0xf, body.bytes()).await?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_notify_tests.rs"]
mod tests;
